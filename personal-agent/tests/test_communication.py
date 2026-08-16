from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from personal_agent.communication.models import (
    CommunicationSource,
    DraftCreate,
    NormalizedMessageCreate,
)
from personal_agent.communication.service import CommunicationService, LinePushAdapter
from personal_agent.communication.store import CommunicationStore
from personal_agent.memory.models import EntityCreate
from personal_agent.memory.store import MemoryStore
from personal_agent.storage import Storage


class FakeAdapter:
    source = CommunicationSource.SLACK

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def send(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {
            "external_message_id": "slack-message-1",
            "provider": "slack",
            "verified": True,
        }


def _service(tmp_path: Path) -> tuple[CommunicationService, MemoryStore]:
    storage = Storage(tmp_path / "communication.sqlite3")
    storage.initialize()
    memory = MemoryStore(storage)
    memory.initialize()
    communication = CommunicationStore(storage)
    communication.initialize()
    return CommunicationService(communication, memory, user_id="primary"), memory


def test_normalized_messages_are_threaded_searchable_and_untrusted(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    timestamp = datetime.now(UTC).isoformat()
    for index, text in enumerate(("来週の新幹線を相談", "窓側で予約候補を確認"), start=1):
        assert service.ingest(
            NormalizedMessageCreate(
                message_id=f"m-{index}",
                source=CommunicationSource.SLACK,
                conversation_id="C123",
                thread_id="T456",
                timestamp=timestamp,
                text=text,
                permissions=["messages.read"],
                source_reference=f"slack://C123/T456/m-{index}",
            )
        )

    hits = service.store.search("新幹線")
    thread = service.store.thread(
        source=CommunicationSource.SLACK,
        conversation_id="C123",
        thread_id="T456",
    )

    assert hits[0].source_reference == "slack://C123/T456/m-1"
    assert hits[0].trust_level == "untrusted"
    assert [item.message_id for item in thread] == ["m-1", "m-2"]
    assert (
        service.ingest(
            NormalizedMessageCreate(
                message_id="m-1",
                source=CommunicationSource.SLACK,
                conversation_id="C123",
                thread_id="T456",
                timestamp=timestamp,
                text="duplicate",
                source_reference="slack://duplicate",
            )
        )
        is False
    )


@pytest.mark.asyncio
async def test_draft_and_send_are_separate_and_require_exact_entity_identity(
    tmp_path: Path,
) -> None:
    service, memory = _service(tmp_path)
    entity = memory.create_entity(
        user_id="primary",
        entity=EntityCreate(
            entity_type="person",
            canonical_name="田中さん",
            aliases=["田中"],
            metadata={"communication": {"slack": {"conversation_id": "D123EXACT"}}},
        ),
    )
    adapter = FakeAdapter()
    service.register(adapter, scopes=["messages.read", "messages.write"])

    draft = service.draft(
        task_id="task-communication",
        draft=DraftCreate(
            source=CommunicationSource.SLACK,
            recipient_entity_id=entity["entity_id"],
            text="確認しました。",
            thread_id="T1",
        ),
    )
    assert draft.state == "draft"
    assert adapter.calls == []

    sent = await service.send(
        draft_id=draft.draft_id,
        idempotency_key="send-key-1",
        action_id="action-1",
    )
    duplicate = await service.send(
        draft_id=draft.draft_id,
        idempotency_key="send-key-2",
        action_id="action-2",
    )

    assert sent.state == "sent"
    assert duplicate.external_message_id == "slack-message-1"
    assert len(adapter.calls) == 1
    assert adapter.calls[0]["conversation_id"] == "D123EXACT"

    with pytest.raises(KeyError):
        service.draft(
            task_id="task-communication",
            draft=DraftCreate(
                source=CommunicationSource.SLACK,
                recipient_entity_id="田中さん",
                text="display name must not resolve",
            ),
        )


@pytest.mark.asyncio
async def test_revoked_connector_cannot_send(tmp_path: Path) -> None:
    service, memory = _service(tmp_path)
    entity = memory.create_entity(
        user_id="primary",
        entity=EntityCreate(
            entity_type="person",
            canonical_name="Recipient",
            metadata={"communication": {"slack": {"conversation_id": "D1"}}},
        ),
    )
    adapter = FakeAdapter()
    service.register(adapter, scopes=["messages.write"])
    draft = service.draft(
        task_id="task",
        draft=DraftCreate(
            source=CommunicationSource.SLACK,
            recipient_entity_id=entity["entity_id"],
            text="hello",
        ),
    )
    service.store.configure_connector(CommunicationSource.SLACK, enabled=False, scopes=[])

    with pytest.raises(PermissionError, match="messages.write"):
        await service.send(
            draft_id=draft.draft_id,
            idempotency_key="revoked-send",
            action_id="action-revoked",
        )
    assert adapter.calls == []

    service.register(adapter, scopes=["messages.read", "messages.write"])
    assert service.store.connector(CommunicationSource.SLACK)["enabled"] is False


@pytest.mark.asyncio
async def test_line_push_uses_uuid_retry_key_and_recognizes_provider_duplicate() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(200, headers={"x-line-request-id": "line-request-1"})
        return httpx.Response(
            409,
            headers={"x-line-accepted-request-id": "line-request-1"},
            json={"message": "The retry key is already accepted"},
        )

    adapter = LinePushAdapter(
        access_token="line-token",
        primary_user_id="U123",
        transport=httpx.MockTransport(handler),
    )
    arguments = {
        "conversation_id": "U123",
        "subject": "",
        "text": "hello",
        "thread_id": None,
        "reply_to": None,
        "idempotency_key": "task:communication.send:stable",
        "task_id": "task",
        "action_id": "action",
    }
    first = await adapter.send(**arguments)
    duplicate = await adapter.send(**arguments)

    retry_key = requests[0].headers["X-Line-Retry-Key"]
    assert len(retry_key) == 36 and retry_key.count("-") == 4
    assert requests[1].headers["X-Line-Retry-Key"] == retry_key
    assert first["verified"] is True
    assert duplicate["verified"] is True
    assert duplicate["provider_duplicate"] is True


@pytest.mark.asyncio
async def test_line_push_marks_network_failure_submitted_unknown() -> None:
    adapter = LinePushAdapter(
        access_token="line-token",
        primary_user_id="U123",
        transport=httpx.MockTransport(
            lambda _request: (_ for _ in ()).throw(httpx.ConnectError("offline"))
        ),
    )
    result = await adapter.send(
        conversation_id="U123",
        subject="",
        text="hello",
        thread_id=None,
        reply_to=None,
        idempotency_key="stable-line-key",
        task_id="task",
        action_id="action",
    )
    assert result == {
        "status": "submitted_unknown",
        "provider": "line",
        "verified": False,
        "resent": False,
    }
