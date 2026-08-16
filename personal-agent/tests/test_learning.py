from __future__ import annotations

from pathlib import Path

import pytest

from personal_agent.learning import LearningService, PreferenceCandidateArgs
from personal_agent.memory import MemoryStore
from personal_agent.memory.models import EventCreate
from personal_agent.storage import Storage
from personal_agent.types import Channel, RiskLevel, TaskState


def _learning(tmp_path: Path) -> tuple[LearningService, MemoryStore, Storage]:
    storage = Storage(tmp_path / "learning.sqlite3")
    storage.initialize()
    memory = MemoryStore(storage)
    memory.initialize()
    learning = LearningService(storage, memory, user_id="primary")
    learning.initialize()
    return learning, memory, storage


def test_preference_learning_requires_evidence_and_user_decision(tmp_path: Path) -> None:
    learning, memory, _ = _learning(tmp_path)
    event = memory.append_event(
        user_id="primary",
        event=EventCreate(
            event_type="choice",
            source="calendar",
            content="午前の会議を3回選んだ",
        ),
    )
    proposal = learning.propose_preference(
        PreferenceCandidateArgs(
            key="calendar.preferred_time",
            value="morning",
            confidence=0.82,
            evidence_event_ids=[event.event_id],
            rationale="Repeated explicit choices",
        )
    )
    assert proposal["state"] == "proposed"
    assert memory.list_preferences(user_id="primary") == []

    accepted = learning.decide_preference(proposal["candidate_id"], accepted=True)
    assert accepted["state"] == "accepted"
    stored = memory.list_preferences(user_id="primary")[0]
    assert stored["value"] == "morning"
    assert stored["evidence_event_ids"] == [event.event_id]

    with pytest.raises(PermissionError):
        learning.propose_preference(
            PreferenceCandidateArgs(
                key="account_password",
                value="should-never-be-learned",
                confidence=1,
                evidence_event_ids=[event.event_id],
                rationale="unsafe",
            )
        )


def test_workflow_learning_only_proposes_repeated_successful_sequences(
    tmp_path: Path,
) -> None:
    learning, _, storage = _learning(tmp_path)
    for index in range(3):
        task = storage.create_task(
            user_id="primary",
            goal=f"workflow {index}",
            source=Channel.WEB,
            conversation_id=f"workflow-{index}",
        )
        for action_index, tool in enumerate(("communication.search", "calendar.create")):
            action_id, _ = storage.begin_action(
                task_id=task.task_id,
                tool_name=tool,
                idempotency_key=f"{index}:{action_index}",
                dry_run=False,
                risk_level=RiskLevel.R1,
                reason="test",
                input_data={},
            )
            storage.finish_action(action_id, status="ok", result={"status": "ok"})
        storage.update_task(task.task_id, state=TaskState.COMPLETED)

    workflows = learning.mine_workflows()
    assert len(workflows) == 1
    assert workflows[0]["occurrences"] == 3
    assert workflows[0]["tool_sequence"] == [
        "communication.search",
        "calendar.create",
    ]
    assert workflows[0]["state"] == "proposed"
    decided = learning.decide_workflow(workflows[0]["workflow_id"], accepted=True)
    assert decided["state"] == "accepted_disabled"
