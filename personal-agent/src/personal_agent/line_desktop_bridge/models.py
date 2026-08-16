from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class VisibleMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: str
    conversation_id: str
    conversation_title: str
    timestamp: str
    text: str
    direction: Literal["incoming", "outgoing", "unknown"] = "unknown"
    kind: Literal["chat_preview", "active_chat"]
    source_reference: str


class SnapshotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    captured_at: str
    line_version: str | None = None
    session_state: Literal["logged_in", "login_required", "unknown"] = "unknown"
    visible_chat_count: int
    active_conversation_id: str | None = None
    messages: list[VisibleMessage]
    screenshot_persisted: bool = False
    may_mark_read: bool = False


class SendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversation_id: str = Field(min_length=16, max_length=128)
    text: str = Field(min_length=1, max_length=5_000)
    idempotency_key: str = Field(min_length=8, max_length=512)
    task_id: str = Field(min_length=1, max_length=128)
    action_id: str = Field(min_length=1, max_length=128)
    approved: bool = False


class SendResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "submitted_unknown", "rejected"]
    external_message_id: str | None = None
    verified: bool = False
    resent: bool = False
    reason_code: str | None = None
