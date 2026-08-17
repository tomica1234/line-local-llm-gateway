from __future__ import annotations

from datetime import date as Date
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TodoType(StrEnum):
    MUST = "must"
    WANT = "want"


class TodoPriority(StrEnum):
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class TodoStatus(StrEnum):
    OPEN = "open"
    COMPLETED = "completed"


class TodoRecurrenceFrequency(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    WEEKDAYS = "weekdays"
    CUSTOM = "custom"


class TodoRecurrence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    frequency: TodoRecurrenceFrequency
    interval: int = Field(default=1, ge=1, le=365)
    count: int | None = Field(default=None, ge=1, le=1_000)
    until: datetime | None = None
    rrule: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_custom(self) -> TodoRecurrence:
        if self.frequency is TodoRecurrenceFrequency.CUSTOM and not self.rrule:
            raise ValueError("Custom Todo recurrence requires an RRULE")
        if self.frequency is not TodoRecurrenceFrequency.CUSTOM and self.rrule:
            raise ValueError("RRULE is only accepted for custom Todo recurrence")
        return self

    @field_validator("rrule")
    @classmethod
    def bounded_rrule(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        allowed = {"FREQ", "INTERVAL", "BYDAY", "COUNT", "UNTIL"}
        for component in normalized.removeprefix("RRULE:").split(";"):
            if "=" not in component or component.split("=", 1)[0] not in allowed:
                raise ValueError("Unsupported custom RRULE component")
        return normalized.removeprefix("RRULE:")


class PersonalTodoCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    todo_type: TodoType = Field(alias="type")
    title: str = Field(min_length=1, max_length=500)
    due_at: Date | datetime | None = None
    remind_at: datetime | None = None
    priority: TodoPriority = TodoPriority.NORMAL
    recurrence: TodoRecurrence | None = None


class PersonalTodoUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=500)
    due_at: Date | datetime | None = None
    remind_at: datetime | None = None
    priority: TodoPriority | None = None
    todo_type: TodoType | None = None
    recurrence: TodoRecurrence | None = None

    @model_validator(mode="after")
    def require_change(self) -> PersonalTodoUpdate:
        if not self.model_fields_set:
            raise ValueError("At least one Todo field must be supplied")
        return self


class PersonalTodo(BaseModel):
    todo_id: str
    user_id: str
    todo_type: TodoType
    title: str
    due_at: Date | datetime | None
    remind_at: datetime | None
    priority: TodoPriority
    status: TodoStatus
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    recurrence: TodoRecurrence | None = None
    reminder_job_id: str | None = None
    source_task_id: str | None = None


class DiaryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    date: Date | None = None
    summary: str = Field(min_length=1, max_length=10_000)
    mood: int | None = Field(default=None, ge=1, le=5)
    good: str | None = Field(default=None, max_length=10_000)
    bad: str | None = Field(default=None, max_length=10_000)
    learned: str | None = Field(default=None, max_length=10_000)
    tomorrow: str | None = Field(default=None, max_length=10_000)
    tags: list[str] = Field(default_factory=list, max_length=50)


class DiaryEntry(BaseModel):
    diary_id: str
    user_id: str
    date: Date
    summary: str
    mood: int | None
    good: str | None
    bad: str | None
    learned: str | None
    tomorrow: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime
