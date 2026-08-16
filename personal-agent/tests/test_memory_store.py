from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from personal_agent.memory.models import (
    EntityCreate,
    EventCreate,
    MemoryCreate,
    PreferenceUpsert,
    PrivacyLevel,
    TrustLevel,
)
from personal_agent.memory.store import MemoryStore
from personal_agent.storage import Storage


@pytest.fixture
def memory_store(settings) -> MemoryStore:
    storage = Storage(settings.db_path)
    storage.initialize()
    store = MemoryStore(storage, default_raw_retention_days=90)
    store.initialize()
    return store


def test_event_sanitization_and_japanese_fts(memory_store: MemoryStore) -> None:
    event = memory_store.append_event(
        user_id="primary",
        event=EventCreate(
            event_type="message.received",
            source="line",
            content="温泉旅行を調べたい。認証コード: 123456",
            payload={"thread": "travel", "access_token": "never-store-this"},
            trust_level=TrustLevel.UNTRUSTED,
        ),
    )

    assert event is not None
    assert event.redacted
    assert "123456" not in event.content
    assert event.payload["access_token"] == "[REDACTED]"
    hits = memory_store.personal_search(user_id="primary", query="温泉旅行")
    assert [hit.record_id for hit in hits] == [event.event_id]


def test_origin_only_event_does_not_index_content(memory_store: MemoryStore) -> None:
    event = memory_store.append_event(
        user_id="primary",
        event=EventCreate(
            event_type="browser.activity",
            source="safari_private",
            content="銀行の振込画面",
            payload={"origin": "https://bank.example", "page_title": "振込"},
            privacy_level=PrivacyLevel.ORIGIN_ONLY,
        ),
    )

    assert event is not None
    assert event.content == ""
    assert event.payload == {"origin": "https://bank.example"}
    assert memory_store.personal_search(user_id="primary", query="振込") == []


def test_memory_deduplicates_and_keeps_evidence(memory_store: MemoryStore) -> None:
    first_event = memory_store.append_event(
        user_id="primary",
        event=EventCreate(event_type="conversation", source="web", content="窓側が好き"),
    )
    second_event = memory_store.append_event(
        user_id="primary",
        event=EventCreate(event_type="conversation", source="voice", content="窓側を希望"),
    )
    assert first_event and second_event
    first = memory_store.remember(
        user_id="primary",
        memory=MemoryCreate(
            statement="新幹線は窓側を好む",
            confidence=0.7,
            evidence_event_ids=[first_event.event_id],
        ),
    )
    second = memory_store.remember(
        user_id="primary",
        memory=MemoryCreate(
            statement="新幹線は窓側を好む",
            confidence=0.9,
            evidence_event_ids=[second_event.event_id],
        ),
    )

    assert first.memory_id == second.memory_id
    assert second.confidence == 0.9
    assert set(second.evidence_event_ids) == {first_event.event_id, second_event.event_id}
    hits = memory_store.search_memories(user_id="primary", query="窓側")
    assert len(hits) == 1


def test_forget_soft_deletes_related_memory(memory_store: MemoryStore) -> None:
    memory = memory_store.remember(
        user_id="primary",
        memory=MemoryCreate(statement="コーヒーは浅煎りが好き"),
    )
    deleted = memory_store.forget(user_id="primary", query="浅煎り")

    assert deleted == [memory.memory_id]
    assert memory_store.search_memories(user_id="primary", query="浅煎り") == []
    with pytest.raises(KeyError):
        memory_store.get_memory(memory.memory_id)


def test_retention_preserves_evidence_tombstone(memory_store: MemoryStore) -> None:
    old_time = datetime.now(UTC) - timedelta(days=10)
    referenced = memory_store.append_event(
        user_id="primary",
        event=EventCreate(
            event_type="message",
            source="line",
            content="長期記憶の根拠",
            timestamp=old_time,
            retention_days=1,
        ),
    )
    unreferenced = memory_store.append_event(
        user_id="primary",
        event=EventCreate(
            event_type="message",
            source="line",
            content="消してよい生イベント",
            timestamp=old_time,
            retention_days=1,
        ),
    )
    assert referenced and unreferenced
    memory_store.remember(
        user_id="primary",
        memory=MemoryCreate(
            statement="長期記憶",
            evidence_event_ids=[referenced.event_id],
        ),
    )

    result = memory_store.purge_expired(now=datetime.now(UTC) + timedelta(days=2))
    assert result == {"events": 2, "event_tombstones": 1, "memories": 0}
    tombstone = memory_store.get_event(referenced.event_id)
    assert tombstone.content == ""
    assert tombstone.redacted
    with pytest.raises(KeyError):
        memory_store.get_event(unreferenced.event_id)


def test_preference_and_entity_are_structured(memory_store: MemoryStore) -> None:
    preference = memory_store.upsert_preference(
        user_id="primary",
        preference=PreferenceUpsert(key="travel.seat", value="window", confidence=0.8),
    )
    entity = memory_store.create_entity(
        user_id="primary",
        entity=EntityCreate(
            entity_type="person",
            canonical_name="山田太郎",
            aliases=["山田", "やまだ"],
        ),
    )

    assert preference["value"] == "window"
    assert memory_store.list_preferences(user_id="primary")[0]["key"] == "travel.seat"
    assert entity["aliases"] == ["山田", "やまだ"]


def test_period_summary_is_idempotent_and_low_importance_memory_decays(
    memory_store: MemoryStore,
) -> None:
    start = datetime.now(UTC) - timedelta(days=2)
    memory_store.append_event(
        user_id="primary",
        event=EventCreate(
            event_type="browser.activity",
            source="safari_private",
            content="京都のホテルを検索した",
            timestamp=start + timedelta(hours=1),
        ),
    )
    summary = memory_store.summarize_period(
        user_id="primary",
        summary_key="daily:2026-08-11",
        start_at=start,
        end_at=start + timedelta(days=1),
    )
    repeated = memory_store.summarize_period(
        user_id="primary",
        summary_key="daily:2026-08-11",
        start_at=start,
        end_at=start + timedelta(days=1),
    )
    assert summary is not None
    assert repeated.memory_id == summary.memory_id
    assert summary.metadata["generated_by"] == "deterministic_compactor"

    with memory_store.storage.transaction() as connection:
        connection.execute(
            "UPDATE memories SET updated_at=? WHERE memory_id=?",
            ((datetime.now(UTC) - timedelta(days=365)).isoformat(), summary.memory_id),
        )
    assert (
        memory_store.decay_memories(
            user_id="primary", before=datetime.now(UTC) - timedelta(days=180)
        )
        == 1
    )
    assert memory_store.get_memory(summary.memory_id).confidence == pytest.approx(0.76)
