from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from personal_agent.browser_worker.app import create_browser_worker_app
from personal_agent.browser_worker.config import BrowserWorkerSettings
from personal_agent.browser_worker.controller import (
    HumanTakeoverActive,
    PlaywrightController,
    ProfileSession,
)
from personal_agent.browser_worker.models import (
    ActionContext,
    BrowserAction,
    BrowserProfile,
)
from personal_agent.browser_worker.security import (
    quarantine_path,
    validate_navigation_url,
    validate_upload_path,
)
from personal_agent.browser_worker.store import BrowserWorkerStore


class FakeBrowserController:
    def __init__(self) -> None:
        self.calls: list[tuple[BrowserProfile, BrowserAction, BaseModel]] = []
        self.takeover: dict[str, Any] | None = None
        self.filled_values: list[str] = []

    async def execute(
        self,
        profile: BrowserProfile,
        action: BrowserAction,
        params: BaseModel,
        context: ActionContext | None,
    ) -> dict[str, Any]:
        self.calls.append((profile, action, params))
        signals = (
            [{"type": "human_required", "reason": "captcha"}]
            if action is BrowserAction.CLICK_POINT
            else []
        )
        return {
            "result": {"url": "https://example.com", "trust_level": "untrusted"},
            "signals": signals,
        }

    async def list_profiles(self) -> list[dict[str, Any]]:
        return [{"profile": "general", "running": False, "state": "closed"}]

    async def current_url(self, profile: BrowserProfile) -> str:
        return "https://login.example/account"

    async def fill_secret(
        self,
        profile: BrowserProfile,
        *,
        ref: str,
        value: str,
        action: Any,
    ) -> dict[str, Any]:
        self.filled_values.append(value)
        return {"origin_url": await self.current_url(profile), "filled": True}

    async def close_profile(self, profile: BrowserProfile) -> None:
        return None

    async def start_takeover(
        self,
        profile: BrowserProfile,
        *,
        reason: str,
        context: ActionContext,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self.takeover = {
            "profile": profile.value,
            "state": "human",
            "reason": reason,
            "task_id": context.task_id,
            "timeout_seconds": timeout_seconds,
        }
        return self.takeover

    async def release_takeover(self, profile: BrowserProfile, *, outcome: str) -> dict[str, Any]:
        self.takeover = None
        return {"profile": profile.value, "state": "agent", "outcome": outcome}

    async def takeover_status(self, profile: BrowserProfile) -> dict[str, Any]:
        return self.takeover or {"profile": profile.value, "state": "agent"}

    async def reap_timeouts(self) -> list[str]:
        return []

    async def close(self) -> None:
        return None


def _settings(tmp_path: Path) -> BrowserWorkerSettings:
    return BrowserWorkerSettings(
        token="worker-test-token",
        profile_root=tmp_path / "profiles",
        quarantine_root=tmp_path / "quarantine",
        state_db_path=tmp_path / "worker.sqlite3",
        finance_allowlist=("bank.example",),
    )


async def _locks_clear(_profile: BrowserProfile) -> tuple[bool, str]:
    return True, "LOCKS_CLEAR"


def _context(*, key: str = "idempotency-key-1") -> dict[str, Any]:
    return {
        "task_id": "task-1",
        "action_id": "action-1",
        "idempotency_key": key,
        "dry_run": False,
        "reason": "contract test",
        "risk_level": "R0",
    }


def test_worker_auth_typed_primitives_and_idempotency(tmp_path: Path) -> None:
    fake = FakeBrowserController()
    app = create_browser_worker_app(_settings(tmp_path), fake, browser_lock_checker=_locks_clear)
    headers = {"X-Browser-Worker-Token": "worker-test-token"}

    with TestClient(app) as client:
        assert client.get("/v1/profiles").status_code == 401
        missing_context = client.post(
            "/v1/browser/general/open",
            headers=headers,
            json={"params": {"url": "https://example.com"}},
        )
        assert missing_context.status_code == 422

        first = client.post(
            "/v1/browser/general/open",
            headers=headers,
            json={
                "params": {"url": "https://example.com"},
                "context": _context(),
            },
        )
        duplicate = client.post(
            "/v1/browser/general/open",
            headers=headers,
            json={
                "params": {"url": "https://example.com"},
                "context": _context(),
            },
        )

    assert first.status_code == 200
    assert first.json()["status"] == "ok"
    assert duplicate.json()["status"] == "duplicate"
    assert len(fake.calls) == 1


def test_worker_preserves_submitted_unknown_on_idempotent_replay(tmp_path: Path) -> None:
    class UncertainController(FakeBrowserController):
        async def execute(
            self,
            profile: BrowserProfile,
            action: BrowserAction,
            params: BaseModel,
            context: ActionContext | None,
        ) -> dict[str, Any]:
            self.calls.append((profile, action, params))
            raise TimeoutError("result unknown")

    controller = UncertainController()
    app = create_browser_worker_app(
        _settings(tmp_path), controller, browser_lock_checker=_locks_clear
    )
    payload = {
        "params": {"url": "https://example.com"},
        "context": _context(key="unknown-browser-key"),
    }
    with TestClient(app) as client:
        first = client.post(
            "/v1/browser/general/open",
            headers={"X-Browser-Worker-Token": "worker-test-token"},
            json=payload,
        )
        replay = client.post(
            "/v1/browser/general/open",
            headers={"X-Browser-Worker-Token": "worker-test-token"},
            json=payload,
        )

    assert first.json()["status"] == "submitted_unknown"
    assert replay.json()["status"] == "submitted_unknown"
    assert "IDEMPOTENT_REPLAY_SUPPRESSED" in replay.json()["warnings"][1]
    assert len(controller.calls) == 1


def test_submit_without_observed_postcondition_is_not_retried(tmp_path: Path) -> None:
    controller = FakeBrowserController()
    settings = _settings(tmp_path)
    app = create_browser_worker_app(settings, controller, browser_lock_checker=_locks_clear)
    payload = {
        "params": {"ref": "ref-1", "expected_text": "Message sent"},
        "context": _context(key="unknown-submit-key"),
    }
    headers = {"X-Browser-Worker-Token": settings.token}

    with TestClient(app) as client:
        first = client.post("/v1/browser/general/submit", headers=headers, json=payload)
        replay = client.post("/v1/browser/general/submit", headers=headers, json=payload)

    assert first.json()["status"] == "submitted_unknown"
    assert replay.json()["status"] == "submitted_unknown"
    assert "PENDING_RECONCILIATION" in replay.json()["warnings"][-1]
    assert len(controller.calls) == 1


def test_worker_browser_lock_is_checked_before_mutation(tmp_path: Path) -> None:
    async def browser_locked(_profile: BrowserProfile) -> tuple[bool, str]:
        return False, "BROWSER_LOCK_ENABLED"

    controller = FakeBrowserController()
    app = create_browser_worker_app(
        _settings(tmp_path),
        controller,
        browser_lock_checker=browser_locked,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/general/open",
            headers={"X-Browser-Worker-Token": "worker-test-token"},
            json={
                "params": {"url": "https://example.com"},
                "context": _context(key="browser-lock-key"),
            },
        )
    assert response.status_code == 423
    assert response.json()["detail"] == "BROWSER_LOCK_ENABLED"
    assert controller.calls == []


def test_worker_does_not_persist_typed_text_or_vision_coordinates_in_generic_audit(
    tmp_path: Path,
) -> None:
    fake = FakeBrowserController()
    settings = _settings(tmp_path)
    app = create_browser_worker_app(settings, fake, browser_lock_checker=_locks_clear)
    headers = {"X-Browser-Worker-Token": settings.token}
    secret_marker = "never-store-this-value"

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/general/type",
            headers=headers,
            json={
                "params": {"ref": "ref-1", "text": secret_marker},
                "context": _context(key="idempotency-key-type"),
            },
        )
        vision = client.post(
            "/v1/browser/general/click_point",
            headers=headers,
            json={
                "params": {"x": 10, "y": 20, "target": "Continue button"},
                "context": {
                    **_context(key="idempotency-key-point"),
                    "action_id": "action-2",
                },
            },
        )
        audit = client.get("/v1/audit", headers=headers).json()

    assert response.status_code == 200
    assert vision.json()["status"] == "human_required"
    assert secret_marker not in settings.state_db_path.read_bytes().decode("utf-8", errors="ignore")
    assert any(item["details"]["coordinates_recorded"] for item in audit)
    assert all(item["details"].get("input_values_recorded") is False for item in audit)


def test_takeover_start_release_and_reason_are_visible(tmp_path: Path) -> None:
    fake = FakeBrowserController()
    settings = _settings(tmp_path)
    app = create_browser_worker_app(settings, fake, browser_lock_checker=_locks_clear)
    headers = {"X-Browser-Worker-Token": settings.token}

    with TestClient(app) as client:
        started = client.post(
            "/v1/takeover/general/start",
            headers=headers,
            json={"reason": "passkey", "context": _context(key="takeover-key-1")},
        )
        status = client.get("/v1/takeover/general", headers=headers)
        released = client.post(
            "/v1/takeover/general/release",
            headers=headers,
            json={"outcome": "completed"},
        )

    assert started.json()["state"] == "human"
    assert status.json()["reason"] == "passkey"
    assert released.json()["state"] == "agent"


def test_finance_allowlist_and_quarantine_paths_are_enforced(tmp_path: Path) -> None:
    allowed = validate_navigation_url(
        "https://login.bank.example/account",
        profile=BrowserProfile.FINANCE,
        finance_allowlist=("bank.example",),
    )
    assert allowed.startswith("https://")

    for blocked in (
        "https://bank.example.evil.test/",
        "javascript:alert(1)",
        "https://user:password@bank.example/",
    ):
        try:
            validate_navigation_url(
                blocked,
                profile=BrowserProfile.FINANCE,
                finance_allowlist=("bank.example",),
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"URL should have been blocked: {blocked}")

    target = quarantine_path(tmp_path, BrowserProfile.GENERAL, "invoice.pdf.exe")
    assert target.parent == tmp_path / "general"
    assert target.suffix == ".bin"
    assert target.name != "invoice.pdf.exe"


def test_browser_blocks_private_navigation_and_confines_uploads(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="private"):
        validate_navigation_url(
            "http://127.0.0.1:8787/api/secrets",
            profile=BrowserProfile.GENERAL,
            finance_allowlist=(),
        )
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    document = upload_root / "invoice.pdf"
    document.write_bytes(b"pdf")
    assert validate_upload_path(str(document), (upload_root,)) == document.resolve()
    secret = upload_root / ".env"
    secret.write_text("TOKEN=no", encoding="utf-8")
    with pytest.raises(PermissionError, match="Secret"):
        validate_upload_path(str(secret), (upload_root,))
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    with pytest.raises(PermissionError, match="outside"):
        validate_upload_path(str(outside), (upload_root,))

    fake = FakeBrowserController()
    settings = _settings(tmp_path / "app")
    app = create_browser_worker_app(settings, fake, browser_lock_checker=_locks_clear)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/finance/open",
            headers={"X-Browser-Worker-Token": settings.token},
            json={
                "params": {"url": "https://evil.example/"},
                "context": _context(key="finance-denied-key"),
            },
        )
    assert response.status_code == 400
    assert fake.calls == []


@pytest.mark.asyncio
async def test_browser_blocks_private_subresources_not_only_navigation(tmp_path: Path) -> None:
    controller = PlaywrightController(
        _settings(tmp_path), BrowserWorkerStore(tmp_path / "route-worker.sqlite3")
    )

    class Request:
        url = "http://127.0.0.1:8787/api/secrets"

        @staticmethod
        def is_navigation_request() -> bool:
            return False

    class Route:
        request = Request()
        aborted = False
        continued = False

        async def abort(self, _reason: str) -> None:
            self.aborted = True

        async def continue_(self) -> None:
            self.continued = True

    route = Route()
    await controller._route_navigation(route, BrowserProfile.GENERAL)
    assert route.aborted is True
    assert route.continued is False


def test_idempotency_key_cannot_be_reused_for_a_different_action(tmp_path: Path) -> None:
    fake = FakeBrowserController()
    settings = _settings(tmp_path)
    app = create_browser_worker_app(settings, fake, browser_lock_checker=_locks_clear)
    headers = {"X-Browser-Worker-Token": settings.token}

    with TestClient(app) as client:
        assert (
            client.post(
                "/v1/browser/general/open",
                headers=headers,
                json={
                    "params": {"url": "https://example.com"},
                    "context": _context(key="same-key-different-action"),
                },
            ).status_code
            == 200
        )
        reused = client.post(
            "/v1/browser/general/back",
            headers=headers,
            json={
                "params": {},
                "context": _context(key="same-key-different-action"),
            },
        )

    assert reused.status_code == 400
    with sqlite3.connect(settings.state_db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM browser_actions").fetchone()[0] == 1


class _FakePage:
    url = "https://example.com/challenge"

    def is_closed(self) -> bool:
        return False


class _FakeContext:
    def __init__(self, page: _FakePage):
        self.pages = [page]


class _TakeoverController(PlaywrightController):
    def __init__(self, settings: BrowserWorkerSettings, session: ProfileSession):
        store = BrowserWorkerStore(settings.state_db_path)
        store.initialize()
        super().__init__(settings, store)
        self._test_session = session
        self._sessions[BrowserProfile.GENERAL] = session

    async def _session(self, profile: BrowserProfile) -> ProfileSession:
        return self._test_session

    async def _dispatch(
        self,
        profile: BrowserProfile,
        session: ProfileSession,
        action: BrowserAction,
        params: BaseModel,
        context: ActionContext | None,
    ) -> dict[str, Any]:
        return {"executed": True}

    @staticmethod
    async def _signals(page: Any) -> list[dict[str, str]]:
        return []


async def test_takeover_locks_mutations_and_timeout_keeps_profile_paused(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime, timedelta

    from personal_agent.browser_worker.models import EmptyParams

    settings = _settings(tmp_path)
    page = _FakePage()
    session = ProfileSession(context=_FakeContext(page), active_page=page)
    controller = _TakeoverController(settings, session)
    context = ActionContext.model_validate(_context(key="takeover-controller-key"))

    await controller.start_takeover(
        BrowserProfile.GENERAL,
        reason="captcha",
        context=context,
        timeout_seconds=60,
    )
    try:
        await controller.execute(
            BrowserProfile.GENERAL,
            BrowserAction.BACK,
            EmptyParams(),
            context,
        )
    except HumanTakeoverActive:
        pass
    else:
        raise AssertionError("Mutation must be locked during human takeover")

    assert session.takeover is not None
    session.takeover.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert await controller.reap_timeouts() == ["task-1"]
    status = await controller.takeover_status(BrowserProfile.GENERAL)
    assert status["state"] == "paused"
    try:
        await controller.execute(
            BrowserProfile.GENERAL,
            BrowserAction.BACK,
            EmptyParams(),
            context,
        )
    except HumanTakeoverActive:
        pass
    else:
        raise AssertionError("Mutation must remain locked after takeover timeout")

    released = await controller.release_takeover(BrowserProfile.GENERAL, outcome="completed")
    assert released["state"] == "agent"
