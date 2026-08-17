from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ContactSource(StrEnum):
    MANUAL = "manual"
    GOOGLE = "google"
    GMAIL = "gmail"
    LINE = "line"
    MEMORY = "memory"


class IdentityKind(StrEnum):
    EMAIL = "email"
    PHONE = "phone"
    LINE = "line"
    GOOGLE = "google"


class ContactIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: IdentityKind
    value: str = Field(min_length=1, max_length=512)
    label: str = Field(default="", max_length=100)
    verified: bool = False

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str, info: object) -> str:
        return value.strip()


class ContactCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=500)
    aliases: list[str] = Field(default_factory=list, max_length=100)
    identities: list[ContactIdentity] = Field(default_factory=list, max_length=100)
    entity_id: str | None = Field(default=None, max_length=128)
    source: ContactSource = ContactSource.MANUAL
    external_id: str | None = Field(default=None, max_length=512)


class ContactRecord(BaseModel):
    contact_id: str
    user_id: str
    display_name: str
    aliases: list[str]
    identities: list[ContactIdentity]
    entity_id: str | None
    source: ContactSource
    external_id: str | None
    created_at: str
    updated_at: str


class ResolutionCandidate(BaseModel):
    contact_id: str
    display_name: str
    entity_id: str | None
    confidence: float
    matched_by: str
    destinations: list[ContactIdentity]


class ResolutionResult(BaseModel):
    query: str
    status: str
    selected: ResolutionCandidate | None = None
    candidates: list[ResolutionCandidate] = Field(default_factory=list)
    requires_user_confirmation: bool
