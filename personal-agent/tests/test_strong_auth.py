from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import CredentialDeviceType

from personal_agent.app import create_app
from personal_agent.config import Settings
from personal_agent.storage import Storage
from personal_agent.strong_auth.service import StrongAuthRejected, StrongAuthService
from personal_agent.types import Channel, RiskLevel


def configured_service(tmp_path) -> tuple[StrongAuthService, Storage]:
    settings = Settings(
        db_path=tmp_path / "passkeys.sqlite3",
        admin_token="a" * 32,
        webauthn_rp_id="agent.example.test",
        webauthn_origin="https://agent.example.test",
    )
    storage = Storage(settings.db_path)
    storage.initialize()
    return StrongAuthService(storage, settings), storage


def register_passkey(monkeypatch, service: StrongAuthService) -> str:
    credential_id_bytes = b"iphone-face-id-credential"
    credential_id = bytes_to_base64url(credential_id_bytes)
    start = service.registration_options("iPhone Face ID")
    assert start["public_key"]["authenticatorSelection"]["userVerification"] == "required"
    assert start["public_key"]["authenticatorSelection"]["residentKey"] == "required"

    monkeypatch.setattr(
        "personal_agent.strong_auth.service.verify_registration_response",
        lambda **_kwargs: SimpleNamespace(
            credential_id=credential_id_bytes,
            credential_public_key=b"cose-public-key",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
            user_verified=True,
        ),
    )
    result = service.verify_registration(
        start["challenge_id"],
        {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {"transports": ["internal", "hybrid"]},
        },
    )
    assert result["credential_id"] == credential_id
    assert service.credential_count() == 1
    return credential_id


def test_passkey_registration_login_session_and_single_use(monkeypatch, tmp_path) -> None:
    service, _storage = configured_service(tmp_path)
    credential_id = register_passkey(monkeypatch, service)
    credential_id_bytes = b"iphone-face-id-credential"
    start = service.login_options()
    assert start["public_key"]["userVerification"] == "required"

    monkeypatch.setattr(
        "personal_agent.strong_auth.service.verify_authentication_response",
        lambda **_kwargs: SimpleNamespace(
            credential_id=credential_id_bytes,
            new_sign_count=1,
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
            user_verified=True,
        ),
    )
    outcome = service.verify_authentication(
        start["challenge_id"], {"id": credential_id, "type": "public-key", "response": {}}
    )
    assert outcome.purpose == "login"
    assert outcome.session_token
    assert service.authenticate_session(outcome.session_token)["credential_id"] == credential_id
    with pytest.raises(StrongAuthRejected, match="already been used"):
        service.verify_authentication(
            start["challenge_id"],
            {"id": credential_id, "type": "public-key", "response": {}},
        )


def test_last_passkey_cannot_be_revoked(monkeypatch, tmp_path) -> None:
    service, _storage = configured_service(tmp_path)
    credential_id = register_passkey(monkeypatch, service)
    with pytest.raises(StrongAuthRejected, match="last passkey"):
        service.revoke_credential(credential_id)


def test_face_id_approval_is_bound_and_allows_r4(monkeypatch, tmp_path) -> None:
    service, storage = configured_service(tmp_path)
    credential_id = register_passkey(monkeypatch, service)
    task = storage.create_task(
        user_id="primary",
        goal="high risk operation",
        source=Channel.WEB,
        conversation_id="iphone",
        risk_level=RiskLevel.R4,
    )
    approval = storage.request_approval(
        task_id=task.task_id,
        tool_name="economic.purchase",
        arguments={"item": "ticket", "total": 15000},
        input_summary={"item": "ticket", "total": 15000},
        risk_level=RiskLevel.R4,
        reason="Non-refundable purchase",
    )
    start = service.approval_options(approval["approval_id"])
    assert start["approval"]["arguments_hash"] == approval["arguments_hash"]

    monkeypatch.setattr(
        "personal_agent.strong_auth.service.verify_authentication_response",
        lambda **_kwargs: SimpleNamespace(
            credential_id=b"iphone-face-id-credential",
            new_sign_count=1,
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
            user_verified=True,
        ),
    )
    outcome = service.verify_authentication(
        start["challenge_id"], {"id": credential_id, "type": "public-key", "response": {}}
    )
    decided = storage.get_approval(approval["approval_id"])
    assert outcome.approval["approval_id"] == approval["approval_id"]
    assert decided["state"] == "approved"
    assert decided["decision_method"] == "webauthn_uv"


def test_approval_change_after_challenge_is_rejected(monkeypatch, tmp_path) -> None:
    service, storage = configured_service(tmp_path)
    credential_id = register_passkey(monkeypatch, service)
    task = storage.create_task(
        user_id="primary",
        goal="bound action",
        source=Channel.WEB,
        conversation_id="iphone",
        risk_level=RiskLevel.R5,
    )
    approval = storage.request_approval(
        task_id=task.task_id,
        tool_name="policy.change",
        arguments={"limit": 10000},
        input_summary={"limit": 10000},
        risk_level=RiskLevel.R5,
        reason="Change policy limit",
    )
    start = service.approval_options(approval["approval_id"])
    with storage.transaction() as connection:
        connection.execute(
            "UPDATE approvals SET input_summary_json=? WHERE approval_id=?",
            ('{"limit":999999}', approval["approval_id"]),
        )
    with pytest.raises(StrongAuthRejected, match="binding"):
        service.verify_authentication(
            start["challenge_id"],
            {"id": credential_id, "type": "public-key", "response": {}},
        )


def test_webauthn_configuration_requires_exact_https_origin() -> None:
    Settings(
        webauthn_rp_id="agent.example.test",
        webauthn_origin="https://agent.example.test",
    ).validate_webauthn()
    with pytest.raises(ValueError, match="configured together"):
        Settings(webauthn_rp_id="agent.example.test").validate_webauthn()
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(
            webauthn_rp_id="agent.example.test",
            webauthn_origin="http://agent.example.test",
        ).validate_webauthn()


def test_pwa_exposes_passkey_status_and_security_headers(client: TestClient) -> None:
    response = client.get("/api/webauthn/status")
    assert response.status_code == 200
    assert response.json()["configured"] is False
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    pwa = client.get("/").text
    assert "Face IDでサインイン" in pwa


def test_remote_api_requires_allowed_tailscale_identity_and_passkey(
    monkeypatch, tmp_path
) -> None:
    class Model:
        async def complete(self, _messages) -> str:
            return "local model response"

    settings = Settings(
        db_path=tmp_path / "remote-auth.sqlite3",
        admin_token="a" * 32,
        webauthn_rp_id="agent.example.test",
        webauthn_origin="https://agent.example.test",
        tailscale_allowed_users=("owner@example.com",),
        tailscale_peer_identities=(("100.64.0.10", "owner@example.com"),),
        require_remote_passkey=True,
    )
    app = create_app(settings, Model())
    owner_header = {"Tailscale-User-Login": "OWNER@example.com"}

    with TestClient(app, client=("100.64.0.10", 50000)) as remote:
        # Direct binds use the configured Tailscale source-IP identity mapping;
        # the client-supplied identity header is not an authority.
        assert remote.get("/").status_code == 200
        assert remote.get("/api/health", headers=owner_header).status_code == 200
        assert remote.get("/", headers=owner_header).status_code == 200
        blocked = remote.post(
            "/api/messages",
            headers=owner_header,
            json={"text": "今何時？", "source": "web", "conversation_id": "iphone"},
        )
        assert blocked.status_code == 401
        assert "passkey" in blocked.json()["detail"]
        with pytest.raises(WebSocketDisconnect):
            with remote.websocket_connect(
                "/api/channels/voice/ws", headers=owner_header
            ):
                pass

        service = app.state.runtime.strong_auth
        credential_id = register_passkey(monkeypatch, service)
        start = service.login_options()
        monkeypatch.setattr(
            "personal_agent.strong_auth.service.verify_authentication_response",
            lambda **_kwargs: SimpleNamespace(
                credential_id=b"iphone-face-id-credential",
                new_sign_count=1,
                credential_device_type=CredentialDeviceType.MULTI_DEVICE,
                credential_backed_up=True,
                user_verified=True,
            ),
        )
        outcome = service.verify_authentication(
            start["challenge_id"],
            {"id": credential_id, "type": "public-key", "response": {}},
        )
        authenticated_headers = {
            **owner_header,
            "Cookie": f"{service.cookie_name}={outcome.session_token}",
        }
        allowed = remote.post(
            "/api/messages",
            headers=authenticated_headers,
            json={"text": "今何時？", "source": "web", "conversation_id": "iphone"},
        )
        assert allowed.status_code == 200
        assert allowed.json()["state"] == "COMPLETED"
        with remote.websocket_connect(
            "/api/channels/voice/ws", headers=authenticated_headers
        ) as websocket:
            websocket.send_json(
                {"text": "今何時？", "source": "voice", "conversation_id": "iphone-voice"}
            )
            assert websocket.receive_json()["state"] == "COMPLETED"
        assert (
            remote.post(
                "/api/messages",
                headers={
                    **authenticated_headers,
                    "Tailscale-User-Login": "attacker@example.com",
                },
                json={"text": "今何時？", "source": "web", "conversation_id": "iphone"},
            ).status_code
            == 200
        )

    with TestClient(app, client=("100.64.0.11", 50002)) as unknown_peer:
        assert unknown_peer.get("/", headers=owner_header).status_code == 403

    with TestClient(app, client=("127.0.0.1", 50001)) as local:
        assert (
            local.post(
                "/api/messages",
                json={"text": "今何時？", "source": "web", "conversation_id": "local"},
            ).status_code
            == 200
        )
        proxied = local.post(
            "/api/messages",
            headers={
                "Tailscale-User-Login": "owner@example.com",
                "X-Personal-Agent-Remote-Proxy": "tailscale-direct-tls-v1",
                "X-Forwarded-For": "100.64.0.10",
            },
            json={"text": "今何時？", "source": "web", "conversation_id": "tls-proxy"},
        )
        assert proxied.status_code == 401


def test_remote_passkey_enforcement_requires_webauthn_configuration() -> None:
    with pytest.raises(ValueError, match="WebAuthn"):
        Settings(
            admin_token="a" * 32,
            tailscale_allowed_users=("owner@example.com",),
            require_remote_passkey=True,
        ).validate_runtime_security()
