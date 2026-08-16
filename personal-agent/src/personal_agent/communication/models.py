from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CommunicationSource(StrEnum):
    LINE = "line"
    LINE_DESKTOP = "line_desktop"
    SLACK = "slack"
    EMAIL = "email"
    SMS = "sms"


class AttachmentReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attachment_id: str
    filename: str
    media_type: str | None = None
    quarantined: bool = True


class NormalizedMessageCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: str = Field(min_length=1, max_length=512)
    source: CommunicationSource
    conversation_id: str = Field(min_length=1, max_length=512)
    thread_id: str | None = Field(default=None, max_length=512)
    sender_entity_id: str | None = None
    timestamp: str
    text: str = Field(max_length=100_000)
    attachments: list[AttachmentReference] = Field(default_factory=list, max_length=100)
    reply_to: str | None = Field(default=None, max_length=512)
    permissions: list[str] = Field(default_factory=list, max_length=100)
    source_reference: str = Field(min_length=1, max_length=2_000)


class DraftCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: CommunicationSource
    recipient_entity_id: str = Field(min_length=1, max_length=128)
    subject: str = Field(default="", max_length=998)
    text: str = Field(min_length=1, max_length=100_000)
    thread_id: str | None = Field(default=None, max_length=512)
    reply_to: str | None = Field(default=None, max_length=512)


class CommunicationSearchHit(BaseModel):
    message_id: str
    source: CommunicationSource
    conversation_id: str
    thread_id: str | None
    sender_entity_id: str | None
    timestamp: str
    text: str
    source_reference: str
    trust_level: str = "untrusted"


class DraftRecord(BaseModel):
    draft_id: str
    task_id: str
    source: CommunicationSource
    recipient_entity_id: str
    conversation_id: str
    subject: str
    text: str
    thread_id: str | None
    reply_to: str | None
    state: str
    external_message_id: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
