from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from personal_agent.commerce.models import (
    Candidate,
    CommerceKind,
    CommerceQuote,
    ConfirmationEvidence,
)
from personal_agent.commerce.store import CommerceStore
from personal_agent.config import Settings
from personal_agent.doctor import DoctorService
from personal_agent.memory.models import MemoryCreate
from personal_agent.memory.store import MemoryStore
from personal_agent.personal_data.models import PersonalTodoCreate
from personal_agent.personal_data.store import PersonalDataStore
from personal_agent.proactive import ProactiveService
from personal_agent.storage import Storage
from personal_agent.types import Channel


class FakeEmbeddings:
    model_id = "local-test-embedding"

    def embed(self, text: str) -> list[float]:
        return [1.0, 0.0] if any(word in text for word in ("東京", "ホテル", "宿")) else [0.0, 1.0]


def test_commerce_submission_requires_durable_reconciliation_and_never_resends(
    tmp_path: Path,
) -> None:
    storage = Storage(tmp_path / "agent.sqlite3")
    storage.initialize()
    task = storage.create_task(
        user_id="primary", goal="reserve", source=Channel.WEB, conversation_id="test"
    )
    commerce = CommerceStore(storage)
    commerce.initialize()
    workflow = commerce.create(
        task_id=task.task_id,
        kind=CommerceKind.RESERVATION,
        goal="Tokyo hotel",
        constraints={"guests": 1},
    )
    workflow = commerce.set_candidates(
        workflow["workflow_id"],
        [
            Candidate(
                candidate_id="candidate_hotel_a",
                provider="booking.test",
                title="Hotel A",
                source_reference="https://booking.test/a",
                price=Decimal("11000"),
            )
        ],
    )
    commerce.select(workflow["workflow_id"], "candidate_hotel_a")
    commerce.set_quote(
        workflow["workflow_id"],
        CommerceQuote(
            provider_or_site="booking.test",
            item_or_service="Hotel A",
            seller="Hotel A",
            unit_price=Decimal("10000"),
            tax=Decimal("1000"),
            total=Decimal("11000"),
            cancellation_policy="Free until previous day",
        ),
    )
    submitted = commerce.record_submission(
        workflow_id=workflow["workflow_id"],
        task_id=task.task_id,
        idempotency_key="one-submit-key",
        browser_verified=True,
        confirmation_number="ABC-12345",
        booking_id=None,
    )
    duplicate = commerce.record_submission(
        workflow_id=workflow["workflow_id"],
        task_id=task.task_id,
        idempotency_key="one-submit-key",
        browser_verified=True,
        confirmation_number="ABC-12345",
        booking_id=None,
    )
    reconciled = commerce.reconcile(
        workflow["workflow_id"],
        ConfirmationEvidence(
            browser_verified=True,
            confirmation_number="ABC-12345",
            email_confirmation_number="ABC-12345",
            email_message_id="gmail-message-1",
            observed_total=Decimal("11000"),
            observed_currency="JPY",
        ),
    )

    assert submitted["state"] == "PENDING_RECONCILIATION"
    assert duplicate["submit_idempotency_key"] == "one-submit-key"
    assert reconciled["state"] == "CONFIRMED"
    assert reconciled["reconciliation"]["resent"] is False


def test_hybrid_memory_and_supersedes_relation(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "agent.sqlite3")
    storage.initialize()
    memory = MemoryStore(storage, embedding_provider=FakeEmbeddings())
    memory.initialize()
    old = memory.remember(
        user_id="primary",
        memory=MemoryCreate(
            statement="東京では静かなホテルが好み", metadata={"importance": "high"}
        ),
    )
    new = memory.remember(
        user_id="primary",
        memory=MemoryCreate(
            statement="東京では駅に近いホテルを優先する",
            supersedes_memory_id=old.memory_id,
            metadata={"importance": "high", "entities": ["東京"]},
        ),
    )
    memory.remember(user_id="primary", memory=MemoryCreate(statement="コーヒーは浅煎り"))

    hits = memory.search_memories(user_id="primary", query="宿の希望", limit=2)

    assert new.embedding_state == "ready"
    assert hits[0].record_id in {old.memory_id, new.memory_id}
    assert hits[0].metadata["embedding_score"] is not None
    assert memory.relations(new.memory_id)[0]["relation_type"] == "supersedes"


def test_event_driven_todo_proactive_rule_and_database_doctor(tmp_path: Path) -> None:
    db = tmp_path / "agent.sqlite3"
    storage = Storage(db)
    storage.initialize()
    MemoryStore(storage).initialize()
    todos = PersonalDataStore(storage, user_id="primary", timezone="Asia/Tokyo")
    todos.initialize()
    todo = todos.create_todo(
        PersonalTodoCreate(
            type="must",
            title="レポート提出",
            due_at=datetime.now(UTC) + timedelta(hours=2),
        )
    )
    proactive = ProactiveService(storage)
    proactive.initialize()
    proactive.update_settings(
        enabled=True,
        categories={"todo_due": True},
        quiet_hours={"start": "00:00", "end": "00:01"},
    )

    created = proactive.scan()
    database = DoctorService(Settings(db_path=db))._database()

    assert any(item["category"] == "todo_due" for item in created)
    opportunity = next(item for item in created if item["category"] == "todo_due")
    assert opportunity["evidence_event_ids"][0].startswith(f"todo:{todo.todo_id}:")
    assert database.status == "OK"
