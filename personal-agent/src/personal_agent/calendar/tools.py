from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..approval import ApprovalMaterial
from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .models import CalendarEventCreate, CalendarEventUpdate
from .store import CalendarConflict, CalendarStore
from .sync import CalendarSyncService


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


class ProviderSyncArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,50}$")


def calendar_tools(
    store: CalendarStore, sync_service: CalendarSyncService | None = None
) -> list[ToolDefinition[Any]]:
    def material_payload(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_title": value.get("title"),
            "start": value.get("start_at"),
            "end": value.get("end_at"),
            "timezone": value.get("timezone"),
            "location": value.get("location"),
            "attendees": value.get("attendees", []),
            "description": value.get("description", ""),
            "recurrence": value.get("recurrence"),
            "reminders": value.get("reminders", []),
            "event_id": value.get("event_id"),
            "operation": value.get("operation"),
        }

    def create_material(args: BaseModel) -> ApprovalMaterial:
        parsed = CreateArgs.model_validate(args)
        payload = material_payload(parsed.model_dump(mode="json"))
        return ApprovalMaterial.create(
            action_type="calendar.create",
            title=f"予定「{parsed.title}」を作成",
            human_summary=f"{parsed.start_at.isoformat()}から予定を作成します。",
            structured_payload=payload,
        )

    def update_material(args: BaseModel) -> ApprovalMaterial:
        parsed = UpdateArgs.model_validate(args)
        current = store.get(parsed.event_id).model_dump(mode="json")
        changes = parsed.update.model_dump(exclude_unset=True, mode="json")
        current.update(changes)
        current["operation"] = "update"
        return ApprovalMaterial.create(
            action_type="calendar.update",
            title=f"予定「{current['title']}」を更新",
            human_summary="表示された変更後の予定内容で更新します。",
            structured_payload=material_payload(current),
        )

    def cancel_material(args: BaseModel) -> ApprovalMaterial:
        parsed = EventIdArgs.model_validate(args)
        current = store.get(parsed.event_id).model_dump(mode="json")
        current["operation"] = "cancel"
        return ApprovalMaterial.create(
            action_type="calendar.cancel",
            title=f"予定「{current['title']}」をキャンセル",
            human_summary=f"{current['start_at']}の予定をキャンセルします。",
            structured_payload=material_payload(current),
        )

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

    async def provider_sync(args: BaseModel, context: ToolContext) -> ToolResult:
        if sync_service is None:
            return ToolResult(
                status="denied", evidence={"reason_code": "CALENDAR_PROVIDER_NOT_CONFIGURED"}
            )
        parsed = ProviderSyncArgs.model_validate(args)
        return ToolResult(
            status="ok",
            reversible=True,
            evidence=await sync_service.sync(parsed.provider, task_id=context.task_id),
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
            approval_material_builder=create_material,
        ),
        ToolDefinition(
            name="calendar.update",
            description="Update an exact event ID after conflict checks.",
            args_model=UpdateArgs,
            handler=update,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("calendar.write",),
            approval_material_builder=update_material,
        ),
        ToolDefinition(
            name="calendar.cancel",
            description="Cancel an exact event ID without deleting its audit history.",
            args_model=EventIdArgs,
            handler=cancel,
            risk_level=RiskLevel.R2,
            mutation=True,
            required_permissions=("calendar.write",),
            approval_material_builder=cancel_material,
        ),
        ToolDefinition(
            name="calendar.provider_sync",
            description=(
                "Synchronize a configured provider through the privileged connector; "
                "local pending changes are never overwritten on conflict."
            ),
            args_model=ProviderSyncArgs,
            handler=provider_sync,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("calendar.read",),
        ),
    ]
