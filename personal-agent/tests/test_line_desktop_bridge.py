from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient

from personal_agent.app import create_app, sync_line_desktop_once
from personal_agent.config import Settings
from personal_agent.line_desktop import LineDesktopBridgeClient
from personal_agent.line_desktop_bridge.app import create_line_desktop_bridge_app
from personal_agent.line_desktop_bridge.config import LineDesktopBridgeSettings
from personal_agent.line_desktop_bridge.models import (
    SendRequest,
    SendResponse,
    SnapshotResponse,
    VisibleMessage,
)
from personal_agent.line_desktop_bridge.store import LineDesktopBridgeStore
from personal_agent.line_desktop_bridge.windows_backend import (
    OcrToken,
    WindowCapture,
    WindowsLineDesktopBackend,
    _conversation_id,
)


class FakeBackend:
    async def snapshot(self) -> SnapshotResponse:
        return SnapshotResponse(
            captured_at="2026-08-16T10:00:00+00:00",
            visible_chat_count=1,
            messages=[
                VisibleMessage(
                    message_id="ldm-1",
                    conversation_id="ld-conversation",
                    conversation_title="安全なテスト",
                    timestamp="2026-08-16T10:00:00+00:00",
                    text="明日の予定を確認",
                    kind="chat_preview",
                    source_reference="line-desktop://ld-conversation/preview",
                )
            ],
        )

    async def send(self, _request: SendRequest) -> SendResponse:
        return SendResponse(status="rejected", reason_code="LINE_DESKTOP_SEND_DISABLED")


class FakeModel:
    async def complete(self, _messages: Any) -> str:
        return "ok"


def bridge_settings(tmp_path: Path) -> LineDesktopBridgeSettings:
    return LineDesktopBridgeSettings(
        token="b" * 48,
        database_path=tmp_path / "bridge.sqlite3",
    )


def test_bridge_requires_token_and_never_returns_screenshot(tmp_path: Path) -> None:
    app = create_line_desktop_bridge_app(bridge_settings(tmp_path), FakeBackend())
    with TestClient(app) as client:
        assert client.post("/v1/snapshot").status_code == 401
        response = client.post(
            "/v1/snapshot", headers={"X-Line-Desktop-Token": "b" * 48}, json={}
        )
    assert response.status_code == 200
    assert response.json()["screenshot_persisted"] is False
    assert response.json()["messages"][0]["text"] == "明日の予定を確認"
    assert "image" not in response.json()


def test_bridge_store_enforces_send_idempotency_without_storing_message_text(
    tmp_path: Path,
) -> None:
    store = LineDesktopBridgeStore(tmp_path / "bridge.sqlite3")
    store.initialize()
    first = store.claim_send("stable-key", conversation_id="ld-1", text="こんにちは")
    replay = store.claim_send("stable-key", conversation_id="ld-1", text="こんにちは")
    assert first["claimed"] is True
    assert replay["claimed"] is False
    with store._connect() as connection:
        row = connection.execute("SELECT * FROM send_actions").fetchone()
    assert "こんにちは" not in " ".join(str(value) for value in dict(row).values())


async def test_desktop_send_rechecks_recipient_and_verifies_visible_outgoing_text(
    tmp_path: Path,
) -> None:
    conversation_id = _conversation_id("Alice")
    settings = LineDesktopBridgeSettings(
        token="b" * 48,
        database_path=tmp_path / "bridge.sqlite3",
        send_enabled=True,
        send_allowlist=(conversation_id,),
    )
    store = LineDesktopBridgeStore(settings.database_path)
    store.initialize()
    store.remember_conversation(conversation_id, "Alice")
    backend = object.__new__(WindowsLineDesktopBackend)
    backend.settings = settings
    backend.store = store
    backend._operation_lock = asyncio.Lock()

    class Image:
        width = 1_000
        height = 700

        def __init__(self, stage: int):
            self.stage = stage

    captures = [
        WindowCapture(
            image=Image(stage),
            list_rows=((0, 100, 300, 170),),
            list_right=300,
            session_state="logged_in",
            window_handle=1,
            was_minimized=False,
        )
        for stage in range(3)
    ]
    capture_index = 0

    def capture(*, keep_open: bool = False) -> WindowCapture:
        nonlocal capture_index
        assert keep_open is True
        result = captures[capture_index]
        capture_index += 1
        return result

    async def ocr(image: Image) -> list[OcrToken]:
        if image.stage == 0:
            return [
                OcrToken(text="Alice", x=20, y=110, width=80, height=20),
                OcrToken(text="Preview", x=20, y=140, width=90, height=20),
            ]
        tokens = [OcrToken(text="Alice", x=400, y=60, width=80, height=20)]
        if image.stage == 2:
            tokens.append(OcrToken(text="Hello", x=800, y=300, width=70, height=20))
        return tokens

    calls = {"clicked": 0, "typed": 0}
    backend._capture_window = capture
    backend._ocr = ocr
    backend._click_conversation = lambda _capture, _row: calls.__setitem__(
        "clicked", calls["clicked"] + 1
    )
    backend._type_and_submit = lambda _capture, _text: calls.__setitem__(
        "typed", calls["typed"] + 1
    )
    backend._restore_minimized = lambda _capture: None
    request = SendRequest(
        conversation_id=conversation_id,
        text="Hello",
        idempotency_key="line-send-stable-key",
        task_id="task-1",
        action_id="action-1",
        approved=True,
    )

    first = await backend.send(request)
    replay = await backend.send(request)

    assert first.status == "ok"
    assert first.verified is True
    assert replay.status == "ok"
    assert replay.reason_code == "IDEMPOTENT_REPLAY"
    assert calls == {"clicked": 1, "typed": 1}
    assert "Hello" not in settings.database_path.read_bytes().decode(errors="ignore")


def test_desktop_send_rejects_duplicate_visible_conversation_titles() -> None:
    backend = object.__new__(WindowsLineDesktopBackend)
    rows = ((0, 100, 300, 170), (0, 180, 300, 250))
    tokens = [
        OcrToken(text="Alice", x=20, y=110, width=80, height=20),
        OcrToken(text="Alice", x=20, y=190, width=80, height=20),
    ]

    result = backend._conversation_rows(tokens, rows)

    assert _conversation_id("Alice") in result
    assert result[_conversation_id("Alice")] is None


async def test_core_client_normalizes_bridge_snapshot() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Line-Desktop-Token"] == "c" * 48
        return httpx.Response(
            200,
            json={
                "captured_at": "2026-08-16T10:00:00+00:00",
                "visible_chat_count": 1,
                "messages": [
                    {
                        "message_id": "ldm-1",
                        "conversation_id": "ld-1",
                        "conversation_title": "テスト",
                        "timestamp": "2026-08-16T10:00:00+00:00",
                        "text": "会議は10時",
                        "direction": "unknown",
                        "kind": "chat_preview",
                        "source_reference": "line-desktop://ld-1/preview",
                    }
                ],
            },
        )

    client = LineDesktopBridgeClient(
        Settings(line_desktop_bridge_token="c" * 48),
        transport=httpx.MockTransport(handler),
    )
    messages = await client.sync_visible()
    assert messages[0].source.value == "line_desktop"
    assert messages[0].text == "テスト: 会議は10時"
    assert messages[0].permissions == ["messages.read"]


async def test_core_sync_ingests_desktop_messages_as_untrusted(tmp_path: Path) -> None:
    app = create_app(
        Settings(db_path=tmp_path / "core.sqlite3", admin_token="a" * 32), FakeModel()
    )

    class FakeClient:
        async def sync_visible(self) -> list[Any]:
            from personal_agent.communication.models import (
                CommunicationSource,
                NormalizedMessageCreate,
            )

            return [
                NormalizedMessageCreate(
                    message_id="desktop-message-1",
                    source=CommunicationSource.LINE_DESKTOP,
                    conversation_id="ld-1",
                    timestamp=datetime.now(UTC).isoformat(),
                    text="外部のメッセージ",
                    permissions=["messages.read"],
                    source_reference="line-desktop://ld-1/desktop-message-1",
                )
            ]

    app.state.runtime.line_desktop = FakeClient()  # type: ignore[assignment]
    result = await sync_line_desktop_once(app.state.runtime)
    hits = app.state.runtime.communication.store.search("外部のメッセージ")
    assert result == {"received": 1, "stored": 1}
    assert hits[0].source.value == "line_desktop"
    assert hits[0].trust_level == "untrusted"


def test_core_push_ingest_requires_bridge_token_and_stores_snapshot(
    tmp_path: Path,
) -> None:
    app = create_app(
        Settings(
            db_path=tmp_path / "core.sqlite3",
            admin_token="a" * 32,
            line_desktop_bridge_token="b" * 48,
        ),
        FakeModel(),
    )
    snapshot = SnapshotResponse(
        captured_at="2026-08-16T10:00:00+00:00",
        visible_chat_count=1,
        messages=[
            VisibleMessage(
                message_id="ldm-push-1",
                conversation_id="ld-push-conversation",
                conversation_title="テスト相手",
                timestamp="2026-08-16T10:00:00+00:00",
                text="同期テスト",
                kind="chat_preview",
                source_reference="line-desktop://ld-push-conversation/preview",
            )
        ],
    ).model_dump(mode="json")
    with TestClient(app) as client:
        assert client.post("/api/channels/line-desktop/ingest", json=snapshot).status_code == 401
        response = client.post(
            "/api/channels/line-desktop/ingest",
            headers={"X-Line-Desktop-Token": "b" * 48},
            json=snapshot,
        )
        status_response = client.get(
            "/api/channels/line-desktop/status",
            headers={"X-Admin-Token": "a" * 32},
        )

    assert response.status_code == 200
    assert response.json() == {"received": 1, "stored": 1}
    assert status_response.json()["bridge"]["status"] == "ok"
    assert status_response.json()["session_state"] == "unknown"
    hits = app.state.runtime.communication.store.search("テスト相手")
    assert len(hits) == 1
    assert hits[0].trust_level == "untrusted"
