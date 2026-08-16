from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TrustLevel(StrEnum):
    SYSTEM = "system"
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class PrivacyLevel(StrEnum):
    STANDARD = "standard"
    ORIGIN_ONLY = "origin_only"
    DROP = "drop"


class MemoryKind(StrEnum):
    EPISODIC = "episodic"
    FACT = "fact"
    PREFERENCE = "preference"
    SUMMARY = "summary"
    COMMITMENT = "commitment"


class EventCreate(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    content: str = Field(default="", max_length=200_000)
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None
    device_id: str | None = Field(default=None, max_length=256)
    provenance: dict[str, Any] = Field(default_factory=dict)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    source_reference: str | None = Field(default=None, max_length=2_000)
    retention_days: int | None = Field(default=None, ge=1, le=3_650)
    privacy_level: PrivacyLevel = PrivacyLevel.STANDARD


class EventRecord(BaseModel):
    event_id: str
    user_id: str
    event_type: str
    source: str
    content: str
    payload: dict[str, Any]
    timestamp: str
    device_id: str | None
    provenance: dict[str, Any]
    trust_level: TrustLevel
    source_reference: str | None
    retention_until: str | None
    redacted: bool
    created_at: str


class MemoryCreate(BaseModel):
    statement: str = Field(min_length=1, max_length=20_000)
    kind: MemoryKind = MemoryKind.FACT
    confidence: float = Field(default=1.0, ge=0, le=1)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=100)
    retention_days: int | None = Field(default=None, ge=1, le=36_500)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryUpdate(BaseModel):
    statement: str | None = Field(default=None, min_length=1, max_length=20_000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    retention_days: int | None = Field(default=None, ge=1, le=36_500)
    metadata: dict[str, Any] | None = None


class MemoryRecord(BaseModel):
    memory_id: str
    user_id: str
    statement: str
    kind: MemoryKind
    confidence: float
    evidence_event_ids: list[str]
    retention_until: str | None
    metadata: dict[str, Any]
    created_at: str
    updated_at: str


class PreferenceUpsert(BaseModel):
    key: str = Field(min_length=1, max_length=256)
    value: Any
    confidence: float = Field(default=1.0, ge=0, le=1)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=100)


class EntityCreate(BaseModel):
    entity_type: str = Field(min_length=1, max_length=100)
    canonical_name: str = Field(min_length=1, max_length=500)
    aliases: list[str] = Field(default_factory=list, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchHit(BaseModel):
    record_type: str
    record_id: str
    source: str
    text: str
    timestamp: str
    score: float
    metadata: dict[str, Any] = Field(default_factory=dict)
