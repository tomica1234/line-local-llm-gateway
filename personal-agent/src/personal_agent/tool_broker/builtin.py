from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from ..storage import Storage
from ..types import RiskLevel, ToolResult
from .broker import ToolContext, ToolDefinition


class EmptyArgs(BaseModel):
    pass


class ScheduleRecurrence(BaseModel):
    frequency: str = Field(pattern="^(daily|weekly)$")
    interval: int = Field(default=1, ge=1, le=365)
    count: int | None = Field(default=None, ge=1, le=1_000)
    until: datetime | None = None


class ScheduleCreateArgs(BaseModel):
    kind: str = Field(pattern="^(timer|alarm|reminder|follow_up|recurring)$")
    run_at: str
    label: str = Field(min_length=1, max_length=500)
    recurrence: ScheduleRecurrence | None = None


class ScheduleCancelArgs(BaseModel):
    job_id: str = Field(min_length=1, max_length=128)


def builtin_tools(storage: Storage) -> list[ToolDefinition[Any]]:
    def system_status(_args: BaseModel, _context: ToolContext) -> ToolResult:
        return ToolResult(
            status="ok",
            evidence={
                "global_pause": storage.get_setting("global_pause"),
                "finance_lock": storage.get_setting("finance_lock"),
                "browser_lock": storage.get_setting("browser_lock"),
                "secret_lock": storage.get_setting("secret_lock"),
                "active_tasks": sum(
                    task.state.value not in {"COMPLETED", "FAILED", "CANCELLED"}
                    for task in storage.list_tasks(limit=500)
                ),
            },
        )

    def scheduler_create(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = ScheduleCreateArgs.model_validate(args.model_dump())
        job_id = storage.create_scheduled_job(
            task_id=context.task_id,
            kind=parsed.kind,
            run_at=parsed.run_at,
            payload={
                "label": parsed.label,
                "recurrence": parsed.recurrence.model_dump(mode="json")
                if parsed.recurrence
                else None,
            },
        )
        return ToolResult(
            status="ok",
            external_id=job_id,
            reversible=True,
            evidence={"job_id": job_id, "run_at": parsed.run_at, "label": parsed.label},
        )

    def scheduler_cancel(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = ScheduleCancelArgs.model_validate(args)
        storage.cancel_scheduled_job(parsed.job_id, task_id=context.task_id)
        return ToolResult(
            status="ok",
            external_id=parsed.job_id,
            evidence={"job_id": parsed.job_id, "cancelled": True},
        )

    return [
        ToolDefinition(
            name="system.status",
            description="Read agent health and safety-lock state.",
            args_model=EmptyArgs,
            handler=system_status,
            risk_level=RiskLevel.R0,
        ),
        ToolDefinition(
            name="scheduler.create",
            description="Create a durable local timer, alarm, or reminder.",
            args_model=ScheduleCreateArgs,
            handler=scheduler_create,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("scheduler.write",),
        ),
        ToolDefinition(
            name="scheduler.cancel",
            description="Cancel a durable scheduled job owned by the current task.",
            args_model=ScheduleCancelArgs,
            handler=scheduler_cancel,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("scheduler.write",),
        ),
    ]
