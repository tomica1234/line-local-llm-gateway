from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from personal_agent.app import create_app, deliver_line_notification_once
from personal_agent.config import Settings
from personal_agent.gateway.line import verify_signature
from personal_agent.types import Channel


def test_line_signature_validation() -> None:
    body = b'{"events":[]}'
    secret = "channel-secret"
    signature = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
    assert verify_signature(body, signature, secret)
    assert not verify_signature(body + b" ", signature, secret)


class FakeModel:
    async def complete(self, _messages: Any) -> str:
        return "ok"


class FakeLinePush:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def send(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {
            "status": "ok",
            "verified": True,
            "external_message_id": "line-request-1",
        }


def _line_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values = {
        "db_path": tmp_path / "line.sqlite3",
        "admin_token": "a" * 32,
        "line_channel_secret": "channel-secret",
        "line_channel_access_token": "channel-access-token",
        "line_primary_user_id": "U-primary",
    }
    values.update(overrides)
    return Settings(**values)


def test_signed_line_webhook_is_the_only_remote_identity_exemption(tmp_path: Path) -> None:
    app = create_app(
        _line_settings(
            tmp_path,
            tailscale_allowed_users=("owner@example.com",),
            require_remote_passkey=False,
        ),
        FakeModel(),
    )
    body = b'{"destination":"bot","events":[]}'
    signature = base64.b64encode(
        hmac.new(b"channel-secret", body, hashlib.sha256).digest()
    ).decode()

    with TestClient(app, client=("203.0.113.20", 50000)) as remote:
        accepted = remote.post(
            "/api/channels/line/webhook",
            content=body,
            headers={"Content-Type": "application/json", "X-Line-Signature": signature},
        )
        rejected = remote.post(
            "/api/channels/line/webhook",
            content=body,
            headers={"Content-Type": "application/json", "X-Line-Signature": "invalid"},
        )
        still_private = remote.get("/")

    assert accepted.status_code == 200
    assert rejected.status_code == 401
    assert still_private.status_code == 403


async def test_due_notification_is_delivered_to_line_without_consuming_pwa_copy(
    tmp_path: Path,
) -> None:
    app = create_app(_line_settings(tmp_path), FakeModel())
    runtime = app.state.runtime
    fake_line = FakeLinePush()
    runtime.line_push = fake_line  # type: ignore[assignment]
    task = runtime.storage.create_task(
        user_id="primary",
        goal="LINE alarm",
        source=Channel.WEB,
        conversation_id="pwa-primary",
    )
    runtime.storage.create_scheduled_job(
        task_id=task.task_id,
        kind="alarm",
        run_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        payload={"label": "薬を飲む"},
    )

    assert await deliver_line_notification_once(runtime) is True
    assert len(fake_line.calls) == 1
    assert fake_line.calls[0]["conversation_id"] == "U-primary"
    assert fake_line.calls[0]["text"] == "薬を飲むの時間です。"
    assert await deliver_line_notification_once(runtime) is False

    pwa_notification = runtime.storage.claim_notification(
        source="web", conversation_id="pwa-primary"
    )
    assert pwa_notification is not None
    assert pwa_notification["text"] == "薬を飲むの時間です。"

    with runtime.storage.read_connection() as connection:
        delivery = connection.execute(
            "SELECT status, attempts, external_id FROM notification_deliveries"
        ).fetchone()
    assert dict(delivery) == {
        "status": "delivered",
        "attempts": 1,
        "external_id": "line-request-1",
    }
