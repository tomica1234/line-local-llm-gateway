from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel

from personal_agent.approval import ApprovalMaterial
from personal_agent.audit import AuditLogger
from personal_agent.core.capabilities import CapabilityStep
from personal_agent.execution import ExecutionStepStatus, ExecutionStore
from personal_agent.policy.engine import PolicyEngine
from personal_agent.storage import Storage
from personal_agent.tool_broker.broker import ToolBroker, ToolContext, ToolDefinition
from personal_agent.types import Channel, RiskLevel, TaskState, ToolResult


class OpaqueArgs(BaseModel):
    draft_id: str


@pytest.mark.asyncio
async def test_approval_material_change_invalidates_approval_before_execution(
    tmp_path: Path,
) -> None:
    storage = Storage(tmp_path / "agent.sqlite3")
    storage.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="send draft",
        source=Channel.WEB,
        conversation_id="test",
        risk_level=RiskLevel.R2,
    )
    destination = {"address": "first@example.test"}
    executed: list[str] = []

    def material(_args: BaseModel) -> ApprovalMaterial:
        return ApprovalMaterial.create(
            action_type="communication.send",
            title="Send message",
            human_summary=f"Send once to {destination['address']}",
            structured_payload={"recipient_actual_address": destination["address"]},
        )

    def send(_args: BaseModel, _context: ToolContext) -> ToolResult:
        executed.append(destination["address"])
        return ToolResult(status="ok", evidence={"verified": True})

    broker = ToolBroker(storage, PolicyEngine(storage), AuditLogger(storage))
    broker.register(
        ToolDefinition(
            name="communication.send",
            description="test",
            args_model=OpaqueArgs,
            handler=send,
            risk_level=RiskLevel.R2,
            mutation=True,
            required_permissions=("messages.write",),
            approval_material_builder=material,
        )
    )
    arguments = {"draft_id": "opaque-1"}
    first = await broker.execute(
        tool_name="communication.send",
        arguments=arguments,
        task_id=task.task_id,
        idempotency_key="first-request",
        dry_run=False,
        reason="test",
        allowed_names={"communication.send"},
        granted_permissions={"messages.write"},
    )
    storage.decide_approval(
        first.evidence["approval_id"], approved=True, actor="primary", method="admin_token"
    )
    destination["address"] = "changed@example.test"

    changed = await broker.execute(
        tool_name="communication.send",
        arguments=arguments,
        task_id=task.task_id,
        idempotency_key="changed-request",
        dry_run=False,
        reason="test",
        allowed_names={"communication.send"},
        granted_permissions={"messages.write"},
    )

    assert changed.status == "denied"
    assert changed.requires_approval is True
    assert changed.evidence["reason_code"] == "APPROVAL_MATERIAL_CHANGED"
    assert executed == []
    assert storage.get_approval(first.evidence["approval_id"])["state"] == "denied"


def test_restart_recovery_never_retries_inflight_mutation(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "agent.sqlite3")
    storage.initialize()
    execution = ExecutionStore(storage)
    execution.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="submit once",
        source=Channel.WEB,
        conversation_id="test",
    )
    step = CapabilityStep(
        step_id="submit",
        purpose="submit exact form",
        allowed_tools=frozenset({"browser.submit"}),
        permissions=frozenset({"browser.submit"}),
        risk=RiskLevel.R2,
    )
    execution.ensure_plan(
        task_id=task.task_id,
        goal=task.goal,
        steps=(step,),
        model="local-test",
        prompt_version="v1",
    )
    execution.start_step(task.task_id, step.step_id, input_data={})
    storage.begin_action(
        task_id=task.task_id,
        tool_name="browser.submit",
        idempotency_key="mutation-before-crash",
        dry_run=False,
        risk_level=RiskLevel.R2,
        reason="test crash boundary",
        input_data={},
        step_id=step.step_id,
        mutation=True,
    )

    recovered = ExecutionStore(storage).recover_incomplete()

    assert recovered == {"resumable": 0, "submitted_unknown": 1}
    assert execution.steps(task.task_id)[0].status is ExecutionStepStatus.SUBMITTED_UNKNOWN
    assert storage.get_task(task.task_id).state is TaskState.SUBMITTED_UNKNOWN
