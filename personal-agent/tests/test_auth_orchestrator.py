from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from personal_agent.auth.service import AuthOrchestrator
from personal_agent.browser_worker.models import (
    ActionContext,
    BrowserAction,
    BrowserProfile,
)
from personal_agent.browser_worker.store import BrowserWorkerStore
from personal_agent.secret.models import SecretAction, SecretCreate, SecretKind
from personal_agent.secret.store import SecretStore

from .test_secret_store import XorTestProtector


class AuthFakeBrowser:
    def __init__(self, snapshots: list[dict[str, Any]]) -> None:
        self.url = "https://login.example/signin"
        self.snapshots = snapshots
        self.snapshot_index = 0
        self.fills: list[tuple[str, str, SecretAction]] = []
        self.clicks: list[str] = []
        self.takeovers: list[str] = []

    async def current_url(self, profile: BrowserProfile) -> str:
        return self.url

    async def execute(
        self,
        profile: BrowserProfile,
        action: BrowserAction,
        params: Any,
        context: ActionContext | None,
    ) -> dict[str, Any]:
        if action is BrowserAction.SNAPSHOT:
            index = min(self.snapshot_index, len(self.snapshots) - 1)
            result = self.snapshots[index]
            self.snapshot_index += 1
            return result
        if action is BrowserAction.CLICK:
            self.clicks.append(params.ref)
        return {"result": {}, "signals": []}

    async def fill_secret(
        self,
        profile: BrowserProfile,
        *,
        ref: str,
        value: str,
        action: SecretAction,
    ) -> dict[str, Any]:
        self.fills.append((ref, value, action))
        return {"filled": True}

    async def start_takeover(
        self,
        profile: BrowserProfile,
        *,
        reason: str,
        context: ActionContext,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self.takeovers.append(reason)
        return {"state": "human", "reason": reason}


def _snapshot(*nodes: dict[str, Any], signals: list[dict[str, str]] | None = None):
    return {"result": {"nodes": list(nodes)}, "signals": signals or []}


def _context() -> ActionContext:
    return ActionContext(
        task_id="auth-task",
        action_id="auth-action",
        idempotency_key="auth-idempotency-key",
        reason="test authentication",
    )


def _services(
    tmp_path: Path, browser: AuthFakeBrowser
) -> tuple[AuthOrchestrator, SecretStore, XorTestProtector, BrowserWorkerStore]:
    protector = XorTestProtector()
    secrets = SecretStore(tmp_path / "secrets.sqlite3", protector)
    secrets.initialize()
    worker = BrowserWorkerStore(tmp_path / "worker.sqlite3")
    worker.initialize()
    return AuthOrchestrator(browser, secrets, worker), secrets, protector, worker


@pytest.mark.asyncio
async def test_existing_session_is_preferred_without_decrypting_secret(tmp_path: Path) -> None:
    browser = AuthFakeBrowser([_snapshot()])
    service, secrets, protector, _ = _services(tmp_path, browser)
    secrets.put(
        SecretCreate(
            credential_id="secret://general/example/main",
            kind=SecretKind.PASSWORD,
            account_label="main",
            allowed_origins=["https://login.example"],
            allowed_actions=[SecretAction.PASSWORD_FILL],
        ),
        "unused-password",
    )

    result = await service.ensure(BrowserProfile.GENERAL, account_label=None, context=_context())

    assert result.status == "already_authenticated"
    assert protector.unprotect_calls == 0
    assert browser.fills == []


@pytest.mark.asyncio
async def test_password_is_filled_directly_and_success_is_verified(tmp_path: Path) -> None:
    browser = AuthFakeBrowser(
        [
            _snapshot(
                {"ref": "ref-1", "role": "textbox", "type": "password", "name": "Password"},
                {"ref": "ref-2", "role": "button", "type": "submit", "name": "Log in"},
                signals=[{"type": "auth_required", "reason": "login_form"}],
            ),
            _snapshot(),
        ]
    )
    service, secrets, _, _ = _services(tmp_path, browser)
    marker = "password-never-returned"
    secrets.put(
        SecretCreate(
            credential_id="secret://general/example/main",
            kind=SecretKind.PASSWORD,
            account_label="main",
            allowed_origins=["https://login.example"],
            allowed_actions=[SecretAction.PASSWORD_FILL],
        ),
        marker,
    )

    result = await service.ensure(BrowserProfile.GENERAL, account_label="main", context=_context())

    assert result.status == "authenticated"
    assert result.reason_code == "PASSWORD_AUTHENTICATED"
    assert browser.fills == [("ref-1", marker, SecretAction.PASSWORD_FILL)]
    assert browser.clicks == ["ref-2"]
    assert marker not in result.model_dump_json()
    assert marker.encode() not in secrets.path.read_bytes()


@pytest.mark.asyncio
async def test_username_then_password_login_uses_encrypted_bundle(tmp_path: Path) -> None:
    browser = AuthFakeBrowser(
        [
            _snapshot(
                {
                    "ref": "ref-1",
                    "role": "textbox",
                    "type": "email",
                    "autocomplete": "username",
                    "name": "Email",
                    "value": None,
                },
                {"ref": "ref-2", "role": "button", "type": "submit", "name": "Next"},
                signals=[{"type": "auth_required", "reason": "username_form"}],
            ),
            _snapshot(
                {"ref": "ref-3", "role": "textbox", "type": "password", "name": "Password"},
                {"ref": "ref-4", "role": "button", "type": "submit", "name": "Log in"},
                signals=[{"type": "auth_required", "reason": "login_form"}],
            ),
            _snapshot(),
        ]
    )
    service, secrets, _, _ = _services(tmp_path, browser)
    for kind, action, value in (
        (SecretKind.USERNAME, SecretAction.USERNAME_FILL, "owner@example.com"),
        (SecretKind.PASSWORD, SecretAction.PASSWORD_FILL, "private-password"),
    ):
        secrets.put(
            SecretCreate(
                credential_id=f"secret://general/example/main/{kind.value}",
                kind=kind,
                account_label="main",
                allowed_origins=["https://login.example"],
                allowed_actions=[action],
            ),
            value,
        )

    result = await service.ensure(
        BrowserProfile.GENERAL, account_label="main", context=_context()
    )

    assert result.status == "authenticated"
    assert browser.fills == [
        ("ref-1", "owner@example.com", SecretAction.USERNAME_FILL),
        ("ref-3", "private-password", SecretAction.PASSWORD_FILL),
    ]
    assert browser.clicks == ["ref-2", "ref-4"]
    assert b"owner@example.com" not in secrets.path.read_bytes()
    assert b"private-password" not in secrets.path.read_bytes()


@pytest.mark.asyncio
async def test_ambiguous_accounts_stop_before_secret_decryption(tmp_path: Path) -> None:
    browser = AuthFakeBrowser(
        [_snapshot({"ref": "ref-1", "role": "textbox", "type": "password", "name": "Password"})]
    )
    service, secrets, protector, _ = _services(tmp_path, browser)
    for name in ("main", "work"):
        secrets.put(
            SecretCreate(
                credential_id=f"secret://general/example/{name}",
                kind=SecretKind.PASSWORD,
                account_label=name,
                allowed_origins=["https://login.example"],
                allowed_actions=[SecretAction.PASSWORD_FILL],
            ),
            f"{name}-password",
        )

    result = await service.ensure(BrowserProfile.GENERAL, account_label=None, context=_context())

    assert result.status == "account_ambiguous"
    assert protector.unprotect_calls == 0
    assert browser.fills == []


@pytest.mark.asyncio
async def test_external_otp_is_task_origin_and_expiry_bound_and_not_persisted(
    tmp_path: Path,
) -> None:
    otp_node = {
        "ref": "ref-3",
        "role": "textbox",
        "type": "text",
        "name": "Verification code",
    }
    button = {"ref": "ref-4", "role": "button", "type": "submit", "name": "Verify"}
    browser = AuthFakeBrowser(
        [_snapshot(otp_node, button), _snapshot(otp_node, button), _snapshot()]
    )
    service, _, _, worker = _services(tmp_path, browser)

    waiting = await service.ensure(BrowserProfile.GENERAL, account_label="main", context=_context())
    assert waiting.status == "waiting_otp"
    assert waiting.auth_session_id

    code = "654321"
    completed = await service.submit_otp(
        BrowserProfile.GENERAL,
        auth_session_id=waiting.auth_session_id,
        code=code,
    )

    assert completed.status == "authenticated"
    assert browser.fills[-1] == ("ref-3", code, SecretAction.TOTP_FILL)
    assert code.encode() not in worker.path.read_bytes()
    session = worker.get_auth_session(waiting.auth_session_id)
    assert session["task_id"] == "auth-task"
    assert session["origin"] == "https://login.example"
    assert session["state"] == "AUTHENTICATED"


@pytest.mark.asyncio
async def test_captcha_enters_human_takeover(tmp_path: Path) -> None:
    browser = AuthFakeBrowser(
        [_snapshot(signals=[{"type": "human_required", "reason": "captcha"}])]
    )
    service, _, _, _ = _services(tmp_path, browser)

    result = await service.ensure(BrowserProfile.GENERAL, account_label=None, context=_context())

    assert result.status == "waiting_user"
    assert browser.takeovers == ["captcha"]
