from __future__ import annotations

import ctypes
import os
import platform
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .storage import Storage
from .tool_broker.broker import ToolContext, ToolDefinition
from .types import RiskLevel, ToolResult


class NotificationArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=2_000)


class EmptyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


def computer_tools(storage: Storage) -> list[ToolDefinition[Any]]:
    def status(_args: BaseModel, _context: ToolContext) -> ToolResult:
        return ToolResult(
            status="ok",
            evidence={
                "platform": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
        )

    def notify(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = NotificationArgs.model_validate(args)
        job_id = storage.create_scheduled_job(
            task_id=context.task_id,
            kind="local_notification",
            run_at=datetime.now(UTC).isoformat(),
            payload={"label": f"{parsed.title}: {parsed.body}"},
        )
        storage.materialize_due_notifications()
        return ToolResult(
            status="ok",
            evidence={
                "job_id": job_id,
                "title": parsed.title,
                "delivery": "durable_agent_notification",
            },
        )

    def lock(_args: BaseModel, _context: ToolContext) -> ToolResult:
        if os.name != "nt":
            raise RuntimeError("computer.lock is only available on Windows")
        if not ctypes.windll.user32.LockWorkStation():
            raise ctypes.WinError()
        return ToolResult(status="ok", evidence={"locked": True})

    return [
        ToolDefinition(
            name="computer.get_status",
            description="Read bounded OS status without shell access.",
            args_model=EmptyArgs,
            handler=status,
            risk_level=RiskLevel.R0,
        ),
        ToolDefinition(
            name="computer.notify",
            description=("Create a local agent notification without arbitrary command execution."),
            args_model=NotificationArgs,
            handler=notify,
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="computer.lock",
            description="Lock the Windows workstation after approval.",
            args_model=EmptyArgs,
            handler=lock,
            risk_level=RiskLevel.R2,
            mutation=True,
        ),
    ]
