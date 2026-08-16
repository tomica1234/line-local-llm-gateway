from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .models import CalendarEventCreate, CalendarEventUpdate
from .store import CalendarConflict, CalendarStore


class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_at: datetime
    end_at: datetime
    query: str | None = Field(default=None, max_length=2_000)
    limit: int = Field(default=50, ge=1, le=100)


class AvailabilityArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_at: datetime
    end_at: datetime


class CreateArgs(CalendarEventCreate):
    pass


class UpdateArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    update: CalendarEventUpdate


class EventIdArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)


def calendar_tools(store: CalendarStore) -> list[ToolDefinition[Any]]:
    def search(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = SearchArgs.model_validate(args)
        events = store.search(
            query=parsed.query,
            start_at=parsed.start_at,
            end_at=parsed.end_at,
            limit=parsed.limit,
        )
        return ToolResult(
            status="ok",
            evidence={"events": [item.model_dump(mode="json") for item in events]},
        )

    def availability(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = AvailabilityArgs.model_validate(args)
        return ToolResult(
            status="ok",
            evidence=store.free_busy(start_at=parsed.start_at, end_at=parsed.end_at),
        )

    def create(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = CreateArgs.model_validate(args)
        try:
            event = store.create(CalendarEventCreate.model_validate(parsed.model_dump()))
        except CalendarConflict as exc:
            return ToolResult(
                status="denied",
                evidence={
                    "reason_code": "CALENDAR_CONFLICT",
                    "conflicts": [item.model_dump(mode="json") for item in exc.conflicts],
                },
                next_action="ask_user_to_resolve_conflict",
            )
        return ToolResult(
            status="ok",
            external_id=event.event_id,
            reversible=True,
            evidence={"event": event.model_dump(mode="json"), "conflict_checked": True},
        )

    def update(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = UpdateArgs.model_validate(args)
        try:
            event = store.update(parsed.event_id, parsed.update)
        except CalendarConflict as exc:
            return ToolResult(
                status="denied",
                evidence={
                    "reason_code": "CALENDAR_CONFLICT",
                    "conflicts": [item.model_dump(mode="json") for item in exc.conflicts],
                },
                next_action="ask_user_to_resolve_conflict",
            )
        return ToolResult(
            status="ok",
            external_id=event.event_id,
            reversible=True,
            evidence={"event": event.model_dump(mode="json"), "conflict_checked": True},
        )

    def cancel(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = EventIdArgs.model_validate(args)
        event = store.cancel(parsed.event_id)
        return ToolResult(
            status="ok",
            external_id=event.event_id,
            evidence={"event": event.model_dump(mode="json"), "cancelled": True},
        )

    return [
        ToolDefinition(
            name="calendar.search",
            description="Search local normalized calendar events in a bounded interval.",
            args_model=SearchArgs,
            handler=search,
            risk_level=RiskLevel.R0,
            required_permissions=("calendar.read",),
        ),
        ToolDefinition(
            name="calendar.get_availability",
            description="Get free/busy intervals without exposing event content.",
            args_model=AvailabilityArgs,
            handler=availability,
            risk_level=RiskLevel.R0,
            required_permissions=("calendar.read",),
        ),
        ToolDefinition(
            name="calendar.create",
            description="Create an event after duplicate and conflict checks.",
            args_model=CreateArgs,
            handler=create,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("calendar.write",),
        ),
        ToolDefinition(
            name="calendar.update",
            description="Update an exact event ID after conflict checks.",
            args_model=UpdateArgs,
            handler=update,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("calendar.write",),
        ),
        ToolDefinition(
            name="calendar.cancel",
            description="Cancel an exact event ID without deleting its audit history.",
            args_model=EventIdArgs,
            handler=cancel,
            risk_level=RiskLevel.R2,
            mutation=True,
            required_permissions=("calendar.write",),
        ),
    ]
