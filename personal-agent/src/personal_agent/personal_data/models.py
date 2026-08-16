from __future__ import annotations

from datetime import date as Date
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class PersonalTodoCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    todo_type: TodoType = Field(alias="type")
    title: str = Field(min_length=1, max_length=500)
    due_at: Date | datetime | None = None
    remind_at: datetime | None = None
    priority: TodoPriority = TodoPriority.NORMAL


class PersonalTodoUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=500)
    due_at: Date | datetime | None = None
    remind_at: datetime | None = None
    priority: TodoPriority | None = None
    todo_type: TodoType | None = None

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
