from __future__ import annotations

import pytest
from pydantic import BaseModel, ConfigDict

from personal_agent.audit import AuditLogger
from personal_agent.policy.engine import PolicyEngine
from personal_agent.storage import Storage
from personal_agent.tool_broker.broker import ToolBroker, ToolDefinition
from personal_agent.tool_broker.builtin import builtin_tools
from personal_agent.types import Channel, RiskLevel, ToolResult


@pytest.mark.asyncio
async def test_mutation_idempotency_prevents_duplicate_job(settings) -> None:
    storage = Storage(settings.db_path)
    storage.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="timer",
        source=Channel.WEB,
        conversation_id="test",
    )
    broker = ToolBroker(storage, PolicyEngine(storage), AuditLogger(storage))
    for tool in builtin_tools(storage):
        broker.register(tool)
    arguments = {"kind": "timer", "run_at": "2026-08-14T08:00:00+09:00", "label": "test"}

    first = await broker.execute(
        tool_name="scheduler.create",
        arguments=arguments,
        task_id=task.task_id,
        idempotency_key="same-key",
        dry_run=False,
        reason="test",
        allowed_names={"scheduler.create"},
    )
    second = await broker.execute(
        tool_name="scheduler.create",
        arguments=arguments,
        task_id=task.task_id,
        idempotency_key="same-key",
        dry_run=False,
        reason="test",
        allowed_names={"scheduler.create"},
    )

    assert first.status == "ok"
    assert second.status == "duplicate"
    assert len(storage.list_scheduled_jobs()) == 1


@pytest.mark.asyncio
async def test_submitted_unknown_replay_remains_unknown_and_is_not_executed(settings) -> None:
    class Args(BaseModel):
        model_config = ConfigDict(extra="forbid")

    calls = 0

    def uncertain(_args, _context) -> ToolResult:
        nonlocal calls
        calls += 1
        return ToolResult(
            status="submitted_unknown",
            evidence={"verified": False},
            next_action="reconcile_before_retry",
        )

    storage = Storage(settings.db_path)
    storage.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="uncertain mutation",
        source=Channel.WEB,
        conversation_id="unknown",
    )
    broker = ToolBroker(storage, PolicyEngine(storage), AuditLogger(storage))
    broker.register(
        ToolDefinition(
            name="test.uncertain",
            description="test",
            args_model=Args,
            handler=uncertain,
            risk_level=RiskLevel.R1,
            mutation=True,
        )
    )
    kwargs = {
        "tool_name": "test.uncertain",
        "arguments": {},
        "task_id": task.task_id,
        "idempotency_key": "uncertain-key",
        "dry_run": False,
        "reason": "test",
        "allowed_names": {"test.uncertain"},
    }
    first = await broker.execute(**kwargs)
    replay = await broker.execute(**kwargs)

    assert first.status == "submitted_unknown"
    assert replay.status == "submitted_unknown"
    assert replay.next_action == "reconcile_before_retry"
    assert "IDEMPOTENT_REPLAY_SUPPRESSED" in replay.warnings[0]
    assert calls == 1
