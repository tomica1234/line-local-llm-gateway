from __future__ import annotations

from pathlib import Path

import pytest

from personal_agent.audit import AuditLogger
from personal_agent.policy.engine import PolicyEngine
from personal_agent.storage import Storage
from personal_agent.tool_broker.broker import ToolBroker, ToolContext, ToolDefinition
from personal_agent.tool_broker.builtin import EmptyArgs
from personal_agent.types import Channel, RiskLevel, ToolResult


def _broker(tmp_path: Path, risk: RiskLevel) -> tuple[ToolBroker, Storage, str, list[str]]:
    storage = Storage(tmp_path / "approvals.sqlite3")
    storage.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="external action",
        source=Channel.WEB,
        conversation_id="approval-test",
        risk_level=risk,
    )
    executions: list[str] = []

    def execute(_args: EmptyArgs, context: ToolContext) -> ToolResult:
        executions.append(context.action_id)
        return ToolResult(status="ok", evidence={"verified": True})

    broker = ToolBroker(storage, PolicyEngine(storage), AuditLogger(storage))
    broker.register(
        ToolDefinition(
            name="browser.click",
            description="test",
            args_model=EmptyArgs,
            handler=execute,
            risk_level=risk,
            mutation=True,
        )
    )
    return broker, storage, task.task_id, executions


@pytest.mark.asyncio
async def test_approval_is_exact_durable_and_single_use(tmp_path: Path) -> None:
    broker, storage, task_id, executions = _broker(tmp_path, RiskLevel.R2)
    first = await broker.execute(
        tool_name="browser.click",
        arguments={},
        task_id=task_id,
        idempotency_key="approval-first-call",
        dry_run=False,
        reason="perform test click",
        allowed_names={"browser.click"},
    )

    assert first.requires_approval is True
    assert executions == []
    approval = storage.list_approvals(state="pending")[0]
    storage.decide_approval(
        approval["approval_id"], approved=True, actor="primary", method="admin_token"
    )

    executed = await broker.execute(
        tool_name="browser.click",
        arguments={},
        task_id=task_id,
        idempotency_key="approval-second-call",
        dry_run=False,
        reason="perform test click",
        allowed_names={"browser.click"},
    )
    replay = await broker.execute(
        tool_name="browser.click",
        arguments={},
        task_id=task_id,
        idempotency_key="approval-third-call",
        dry_run=False,
        reason="perform test click",
        allowed_names={"browser.click"},
    )

    assert executed.status == "ok"
    assert replay.status == "denied"
    assert replay.evidence["reason_code"] == "APPROVAL_ALREADY_CONSUMED"
    assert len(executions) == 1


def test_r4_cannot_be_approved_with_admin_token_only(tmp_path: Path) -> None:
    _, storage, task_id, _ = _broker(tmp_path, RiskLevel.R4)
    approval = storage.request_approval(
        task_id=task_id,
        tool_name="browser.click",
        arguments={},
        input_summary={},
        risk_level=RiskLevel.R4,
        reason="high risk",
    )
    with pytest.raises(PermissionError, match="strong-auth"):
        storage.decide_approval(
            approval["approval_id"],
            approved=True,
            actor="primary",
            method="admin_token",
        )
