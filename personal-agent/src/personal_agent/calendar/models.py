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
        return self


class CalendarEventUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=1_000)
    start_at: datetime | None = None
    end_at: datetime | None = None
    location: str | None = Field(default=None, max_length=2_000)
    description: str | None = Field(default=None, max_length=20_000)
    recurrence: RecurrenceRule | None = None
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
    recurrence: dict[str, Any] | None
    linked_economic_intent_id: str | None
    source_reference: str | None
    created_at: str
    updated_at: str
