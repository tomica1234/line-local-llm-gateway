from __future__ import annotations

from datetime import date, datetime
from zoneinfo import ZoneInfo

import pytest

from personal_agent.audit import AuditLogger
from personal_agent.core.capabilities import build_capability_plan
from personal_agent.personal_data.models import DiaryCreate, PersonalTodoCreate, TodoStatus
from personal_agent.personal_data.store import PersonalDataStore, business_date
from personal_agent.personal_data.tools import personal_data_tools
from personal_agent.policy.engine import PolicyEngine
from personal_agent.portability import DataPortabilityService
from personal_agent.storage import Storage
from personal_agent.tool_broker.broker import ToolBroker
from personal_agent.types import Channel


def test_business_date_uses_previous_day_until_0359_in_tokyo() -> None:
    tokyo = ZoneInfo("Asia/Tokyo")
    assert business_date(datetime(2026, 8, 17, 3, 59, tzinfo=tokyo)) == date(2026, 8, 16)
    assert business_date(datetime(2026, 8, 17, 4, 0, tzinfo=tokyo)) == date(2026, 8, 17)


def test_natural_todo_and_diary_requests_receive_typed_local_capabilities() -> None:
    todo_plan = build_capability_plan("明日までに住民票を提出しないと")
    assert todo_plan[0].allowed_tools == frozenset({"todo.create"})
    diary_plan = build_capability_plan("今日は権限の実装をして嬉しかった")
    assert diary_plan[0].allowed_tools == frozenset({"diary.create"})
    completion_plan = build_capability_plan("住民票を提出した")
    assert [step.allowed_tools for step in completion_plan] == [
        frozenset({"todo.list"}),
        frozenset({"todo.complete"}),
    ]


def test_personal_todo_and_diary_use_separate_structured_tables(tmp_path) -> None:
    storage = Storage(tmp_path / "personal.sqlite3")
    storage.initialize()
    store = PersonalDataStore(storage, user_id="primary", timezone="Asia/Tokyo")
    store.initialize()

    todo = store.create_todo(
        PersonalTodoCreate.model_validate(
            {
                "type": "must",
                "title": "住民票を提出する",
                "due_at": "2026-08-20",
                "remind_at": "2026-08-19T18:00:00+09:00",
                "priority": "high",
            }
        )
    )
    completed = store.complete_todo(todo.todo_id)
    entry = store.create_diary(
        DiaryCreate(
            date=date(2026, 8, 16),
            summary="Personal Agentの権限設計を直した",
            mood=4,
            good="テストが増えた",
            learned="権限はstep単位に固定する",
            tomorrow="CIを確認する",
            tags=["開発", "security"],
        )
    )

    assert completed.status is TodoStatus.COMPLETED
    assert completed.completed_at is not None
    assert store.read_diary(date(2026, 8, 16))[0].diary_id == entry.diary_id
    assert store.search_diary("権限")[0].tags == ["開発", "security"]
    with storage.read_connection() as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert {"tasks", "personal_todos", "diary_entries"}.issubset(tables)
    assert todo.todo_id not in {task.task_id for task in storage.list_tasks()}

    portability = DataPortabilityService(storage, user_id="primary")
    exported = portability.export()["data"]
    assert exported["personal_todos"][0]["todo_id"] == todo.todo_id
    assert exported["diary_entries"][0]["diary_id"] == entry.diary_id
    deleted = portability.delete("personal", confirmation="DELETE:personal")
    assert deleted["deleted"] == {"personal_todos": 1, "diary_entries": 1}


@pytest.mark.asyncio
async def test_personal_data_tools_obey_broker_permissions(tmp_path) -> None:
    storage = Storage(tmp_path / "personal-tools.sqlite3")
    storage.initialize()
    store = PersonalDataStore(storage, user_id="primary", timezone="Asia/Tokyo")
    store.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="Todoを追加",
        source=Channel.WEB,
        conversation_id="personal-tools",
    )
    broker = ToolBroker(storage, PolicyEngine(storage), AuditLogger(storage))
    for definition in personal_data_tools(store):
        broker.register(definition)
    arguments = {"type": "want", "title": "温泉を調べる", "priority": "normal"}

    denied = await broker.execute(
        tool_name="todo.create",
        arguments=arguments,
        task_id=task.task_id,
        idempotency_key="todo-denied",
        dry_run=False,
        reason="permission regression",
        allowed_names={"todo.create"},
        granted_permissions=set(),
        step_id="todo-step",
    )
    created = await broker.execute(
        tool_name="todo.create",
        arguments=arguments,
        task_id=task.task_id,
        idempotency_key="todo-created",
        dry_run=False,
        reason="explicit user request",
        allowed_names={"todo.create"},
        granted_permissions={"todo.write"},
        step_id="todo-step",
    )

    assert denied.evidence["reason_code"] == "PERMISSION_NOT_GRANTED"
    assert created.status == "ok"
    assert store.list_todos()[0].title == "温泉を調べる"
