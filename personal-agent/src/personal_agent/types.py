from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Channel(StrEnum):
    WEB = "web"
    LINE = "line"
    VOICE = "voice"


class TaskState(StrEnum):
    RECEIVED = "RECEIVED"
    UNDERSTANDING = "UNDERSTANDING"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    WAITING_AUTH = "WAITING_AUTH"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    WAITING_USER = "WAITING_USER"
    WAITING_EXTERNAL = "WAITING_EXTERNAL"
    PAUSED = "PAUSED"
    RETRYING = "RETRYING"
    FAILED = "FAILED"
    SUBMITTED_UNKNOWN = "SUBMITTED_UNKNOWN"
    CANCELLED = "CANCELLED"


class RiskLevel(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"


class Route(StrEnum):
    TIER0 = "tier0"
    DEEP = "deep"


class MessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    source: Channel = Channel.WEB
    conversation_id: str = Field(default="default", min_length=1, max_length=256)
    task_id: str | None = None
    dry_run: bool = False


class MessageResponse(BaseModel):
    task_id: str
    state: TaskState
    route: Route
    text: str
    source: Channel
    conversation_id: str
    reason_code: str


class TaskRecord(BaseModel):
    task_id: str
    user_id: str
    goal: str
    state: TaskState
    risk_level: RiskLevel
    route: Route | None = None
    source: Channel
    conversation_id: str
    plan: list[str] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: str
    updated_at: str


class TaskEventRecord(BaseModel):
    event_id: int
    task_id: str
    event_type: str
    state: TaskState | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class ToolResult(BaseModel):
    status: Literal[
        "ok",
        "denied",
        "error",
        "duplicate",
        "dry_run",
        "waiting_auth",
        "waiting_user",
        "submitted_unknown",
    ]
    external_id: str | None = None
    requires_approval: bool = False
    reversible: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    next_action: str | None = None


class HealthResponse(BaseModel):
    status: str
    database: str
    model_endpoint: str
    recovered_tasks: int = 0
