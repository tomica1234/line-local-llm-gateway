from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CalendarStatus(StrEnum):
    TENTATIVE = "tentative"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"


class RecurrenceFrequency(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class RecurrenceRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    frequency: RecurrenceFrequency
    interval: int = Field(default=1, ge=1, le=365)
    count: int | None = Field(default=None, ge=1, le=1_000)
    until: datetime | None = None


class CalendarEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=1_000)
    start_at: datetime
    end_at: datetime
    timezone: str = "Asia/Tokyo"
    location: str | None = Field(default=None, max_length=2_000)
    description: str = Field(default="", max_length=20_000)
    attendees: list[str] = Field(default_factory=list, max_length=200)
    reminders: list[int] = Field(default_factory=list, max_length=20)
    status: CalendarStatus = CalendarStatus.CONFIRMED
    recurrence: RecurrenceRule | None = None
    linked_economic_intent_id: str | None = None
    source_reference: str | None = Field(default=None, max_length=2_000)
    fail_on_conflict: bool = True

    @model_validator(mode="after")
    def valid_interval(self) -> CalendarEventCreate:
        if self.start_at.tzinfo is None or self.end_at.tzinfo is None:
            raise ValueError("Calendar timestamps must include a timezone offset")
        if self.end_at <= self.start_at:
            raise ValueError("Calendar event end must be after start")
        if any(minutes < 0 or minutes > 60 * 24 * 30 for minutes in self.reminders):
            raise ValueError("Calendar reminders must be 0..43200 minutes")
        if any("@" not in attendee for attendee in self.attendees):
            raise ValueError("Calendar attendees must be explicit email addresses")
        return self


class CalendarEventUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=1_000)
    start_at: datetime | None = None
    end_at: datetime | None = None
    location: str | None = Field(default=None, max_length=2_000)
    description: str | None = Field(default=None, max_length=20_000)
    recurrence: RecurrenceRule | None = None
    attendees: list[str] | None = Field(default=None, max_length=200)
    reminders: list[int] | None = Field(default=None, max_length=20)
    fail_on_conflict: bool = True


class CalendarEventRecord(BaseModel):
    event_id: str
    title: str
    start_at: str
    end_at: str
    timezone: str
    location: str | None
    description: str
    status: CalendarStatus
    recurrence: dict[str, Any] | list[str] | None
    attendees: list[str] = Field(default_factory=list)
    reminders: list[int] = Field(default_factory=list)
    linked_economic_intent_id: str | None
    source_reference: str | None
    created_at: str
    updated_at: str
    provider: str = "local"
    external_event_id: str | None = None
    external_version: str | None = None
    last_synced_at: str | None = None
    sync_state: str = "local_only"
