from __future__ import annotations

from datetime import date as Date
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .models import DiaryCreate, PersonalTodoCreate, PersonalTodoUpdate, TodoStatus
from .store import PersonalDataStore


class TodoIdArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    todo_id: str = Field(min_length=1, max_length=128)


class TodoListArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: TodoStatus | None = TodoStatus.OPEN
    limit: int = Field(default=100, ge=1, le=500)


class TodoUpdateArgs(PersonalTodoUpdate):
    todo_id: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def require_todo_change(self) -> TodoUpdateArgs:
        if not (self.model_fields_set - {"todo_id"}):
            raise ValueError("At least one Todo field must be supplied")
        return self

    def update_value(self) -> PersonalTodoUpdate:
        return PersonalTodoUpdate.model_validate(
            self.model_dump(exclude={"todo_id"}, exclude_unset=True)
        )


class DiaryReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    date: Date | None = None


class DiarySearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    keyword: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=50, ge=1, le=200)


def personal_data_tools(store: PersonalDataStore) -> list[ToolDefinition[Any]]:
    def todo_create(args: BaseModel, _context: ToolContext) -> ToolResult:
        todo = store.create_todo(PersonalTodoCreate.model_validate(args))
        return ToolResult(status="ok", reversible=True, evidence=todo.model_dump(mode="json"))

    def todo_list(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = TodoListArgs.model_validate(args)
        todos = store.list_todos(status=parsed.status, limit=parsed.limit)
        return ToolResult(
            status="ok",
            evidence={"todos": [todo.model_dump(mode="json") for todo in todos]},
        )

    def todo_complete(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = TodoIdArgs.model_validate(args)
        todo = store.complete_todo(parsed.todo_id)
        return ToolResult(status="ok", reversible=True, evidence=todo.model_dump(mode="json"))

    def todo_update(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = TodoUpdateArgs.model_validate(args)
        todo = store.update_todo(parsed.todo_id, parsed.update_value())
        return ToolResult(status="ok", reversible=True, evidence=todo.model_dump(mode="json"))

    def diary_create(args: BaseModel, _context: ToolContext) -> ToolResult:
        entry = store.create_diary(DiaryCreate.model_validate(args))
        return ToolResult(status="ok", reversible=True, evidence=entry.model_dump(mode="json"))

    def diary_read(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = DiaryReadArgs.model_validate(args)
        entries = store.read_diary(parsed.date)
        return ToolResult(
            status="ok",
            evidence={"entries": [entry.model_dump(mode="json") for entry in entries]},
        )

    def diary_search(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = DiarySearchArgs.model_validate(args)
        entries = store.search_diary(parsed.keyword, limit=parsed.limit)
        return ToolResult(
            status="ok",
            evidence={"entries": [entry.model_dump(mode="json") for entry in entries]},
        )

    return [
        ToolDefinition(
            name="todo.create",
            description="Create a structured PersonalTodo, distinct from an Agent execution Task.",
            args_model=PersonalTodoCreate,
            handler=todo_create,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("todo.write",),
        ),
        ToolDefinition(
            name="todo.list",
            description="List the primary user's structured PersonalTodo records.",
            args_model=TodoListArgs,
            handler=todo_list,
            risk_level=RiskLevel.R0,
            required_permissions=("todo.read",),
        ),
        ToolDefinition(
            name="todo.complete",
            description="Complete one exact PersonalTodo ID; ambiguous titles are not accepted.",
            args_model=TodoIdArgs,
            handler=todo_complete,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("todo.write",),
        ),
        ToolDefinition(
            name="todo.update",
            description="Update explicit fields on one exact PersonalTodo ID.",
            args_model=TodoUpdateArgs,
            handler=todo_update,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("todo.write",),
        ),
        ToolDefinition(
            name="diary.create",
            description=(
                "Create a structured diary entry. If date is omitted, 00:00-03:59 Asia/Tokyo "
                "uses the previous business date."
            ),
            args_model=DiaryCreate,
            handler=diary_create,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("diary.write",),
        ),
        ToolDefinition(
            name="diary.read",
            description=(
                "Read diary entries for a date. If omitted, use the Asia/Tokyo business date."
            ),
            args_model=DiaryReadArgs,
            handler=diary_read,
            risk_level=RiskLevel.R0,
            required_permissions=("diary.read",),
        ),
        ToolDefinition(
            name="diary.search",
            description="Search structured diary fields and tags by a bounded keyword.",
            args_model=DiarySearchArgs,
            handler=diary_search,
            risk_level=RiskLevel.R0,
            required_permissions=("diary.read",),
        ),
    ]
