from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from personal_agent.browser_worker.app import create_browser_worker_app
from personal_agent.browser_worker.models import BrowserProfile
from personal_agent.secret.models import SecretAction, SecretCreate, SecretKind
from personal_agent.secret.store import SecretStore, normalize_origin, totp_code

from .test_browser_worker import FakeBrowserController, _context, _settings


class XorTestProtector:
    name = "test-only-xor"

    def __init__(self) -> None:
        self.unprotect_calls = 0

    def protect(self, plaintext: bytes) -> bytes:
        return bytes(item ^ 0xA5 for item in plaintext)

    def unprotect(self, ciphertext: bytes) -> bytes:
        self.unprotect_calls += 1
        return bytes(item ^ 0xA5 for item in ciphertext)


def _secret_store(tmp_path: Path) -> tuple[SecretStore, XorTestProtector]:
    protector = XorTestProtector()
    store = SecretStore(tmp_path / "secrets.sqlite3", protector)
    store.initialize()
    return store, protector


def test_encrypted_secret_store_origin_action_and_metadata_boundaries(tmp_path: Path) -> None:
    store, _ = _secret_store(tmp_path)
    marker = "not-present-in-the-database"
    metadata = store.put(
        SecretCreate(
            credential_id="secret://travel/example/main",
            kind=SecretKind.PASSWORD,
            account_label="Example main",
            allowed_origins=["https://login.example/account"],
            allowed_actions=[SecretAction.PASSWORD_FILL],
        ),
        marker,
    )

    assert metadata.allowed_origins == ["https://login.example"]
    assert marker.encode() not in store.path.read_bytes()
    assert not hasattr(metadata, "value")
    assert (
        store.value_for_use(
            credential_id=metadata.credential_id,
            origin="https://login.example/another/path?token=discarded",
            action=SecretAction.PASSWORD_FILL,
            task_id="task-1",
        )
        == marker
    )
    try:
        store.value_for_use(
            credential_id=metadata.credential_id,
            origin="https://login.example.evil.test",
            action=SecretAction.PASSWORD_FILL,
            task_id="task-1",
        )
    except PermissionError:
        pass
    else:
        raise AssertionError("A credential must be bound to the exact allowed origin")


def test_totp_matches_rfc_vector_and_origin_normalization() -> None:
    assert totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now=59, digits=8) == "94287082"
    assert normalize_origin("HTTPS://例え.jp:443/login") == "https://xn--r8jz45g.jp"


def test_worker_direct_fill_never_returns_or_logs_secret_value(tmp_path: Path) -> None:
    secret_store, protector = _secret_store(tmp_path)
    marker = "worker-direct-fill-marker"
    secret_store.put(
        SecretCreate(
            credential_id="secret://general/example/main",
            kind=SecretKind.PASSWORD,
            account_label="Example main",
            allowed_origins=["https://login.example"],
            allowed_actions=[SecretAction.PASSWORD_FILL],
        ),
        marker,
    )
    controller = FakeBrowserController()
    settings = _settings(tmp_path)

    async def locks_clear(_profile: BrowserProfile) -> tuple[bool, str]:
        return True, "LOCKS_CLEAR"

    app = create_browser_worker_app(
        settings,
        controller,
        secret_store=secret_store,
        secret_lock_checker=locks_clear,
    )
    headers = {"X-Browser-Worker-Token": settings.token}
    with TestClient(app) as client:
        response = client.post(
            "/v1/secret/general/fill",
            headers=headers,
            json={
                "credential_ref": "secret://general/example/main",
                "ref": "ref-1",
                "action": "password_fill",
                "context": _context(key="secret-fill-idempotency-key"),
            },
        )
        duplicate = client.post(
            "/v1/secret/general/fill",
            headers=headers,
            json={
                "credential_ref": "secret://general/example/main",
                "ref": "ref-1",
                "action": "password_fill",
                "context": _context(key="secret-fill-idempotency-key"),
            },
        )
        audit = client.get("/v1/audit", headers=headers).json()

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert marker not in response.text
    assert duplicate.json()["status"] == "duplicate"
    assert controller.filled_values == [marker]
    assert protector.unprotect_calls == 1
    assert marker not in str(audit)
    assert secret_store.usage()[0] == {
        "credential_id": "secret://general/example/main",
        "task_id": "task-1",
        "origin": "https://login.example",
        "action": "password_fill",
        "result": "ok",
        "created_at": secret_store.usage()[0]["created_at"],
    }


def test_worker_can_store_username_via_write_only_api(tmp_path: Path) -> None:
    secret_store, _ = _secret_store(tmp_path)
    controller = FakeBrowserController()

    async def locks_clear(_profile: BrowserProfile) -> tuple[bool, str]:
        return True, "LOCKS_CLEAR"

    app = create_browser_worker_app(
        _settings(tmp_path),
        controller,
        secret_store=secret_store,
        secret_lock_checker=locks_clear,
    )
    marker = "private-owner@example.com"
    with TestClient(app) as client:
        response = client.post(
            "/v1/secrets",
            headers={"X-Browser-Worker-Token": "worker-test-token"},
            json={
                "credential_id": "secret://general/example/main/username",
                "kind": "username",
                "account_label": "main",
                "allowed_origins": ["https://login.example/path"],
                "allowed_actions": ["username_fill"],
                "value": marker,
            },
        )
        audit = client.get(
            "/v1/audit",
            headers={"X-Browser-Worker-Token": "worker-test-token"},
        ).json()

    assert response.status_code == 200
    assert response.json()["kind"] == "username"
    assert "value" not in response.json()
    assert marker not in response.text
    assert marker.encode() not in secret_store.path.read_bytes()
    assert marker not in str(audit)


def test_secret_lock_is_checked_before_decryption(tmp_path: Path) -> None:
    secret_store, protector = _secret_store(tmp_path)
    secret_store.put(
        SecretCreate(
            credential_id="secret://general/example/main",
            kind=SecretKind.PASSWORD,
            account_label="Example main",
            allowed_origins=["https://login.example"],
            allowed_actions=[SecretAction.PASSWORD_FILL],
        ),
        "locked-value",
    )
    controller = FakeBrowserController()

    async def locked(_profile: BrowserProfile) -> tuple[bool, str]:
        return False, "SECRET_LOCK_ENABLED"

    app = create_browser_worker_app(
        _settings(tmp_path),
        controller,
        secret_store=secret_store,
        secret_lock_checker=locked,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/secret/general/fill",
            headers={"X-Browser-Worker-Token": "worker-test-token"},
            json={
                "credential_ref": "secret://general/example/main",
                "ref": "ref-1",
                "action": "password_fill",
                "context": _context(key="locked-secret-fill-key"),
            },
        )

    assert response.status_code == 423
    assert protector.unprotect_calls == 0
    assert controller.filled_values == []
