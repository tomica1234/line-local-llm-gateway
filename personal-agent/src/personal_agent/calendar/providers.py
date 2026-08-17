from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from ..browser.client import BrowserWorkerClient
from .models import CalendarEventCreate, CalendarEventUpdate
from .store import CalendarStore


class ProviderEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    provider: str
    external_event_id: str
    version: str | None = None
    title: str
    start_at: str
    end_at: str
    timezone: str = "Asia/Tokyo"
    location: str | None = None
    description: str = ""
    status: str = "confirmed"
    recurrence: list[str] = Field(default_factory=list)
    attendees: list[str] = Field(default_factory=list)
    reminders: list[int] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class CalendarProvider(Protocol):
    name: str

    async def list(
        self, *, task_id: str, start_at: datetime, end_at: datetime, query: str | None = None
    ) -> list[ProviderEvent]: ...

    async def get(self, *, task_id: str, event_id: str) -> ProviderEvent: ...

    async def free_busy(
        self, *, task_id: str, start_at: datetime, end_at: datetime
    ) -> dict[str, Any]: ...

    async def create(self, *, task_id: str, event: CalendarEventCreate) -> ProviderEvent: ...

    async def update(
        self, *, task_id: str, event_id: str, update: CalendarEventUpdate
    ) -> ProviderEvent: ...

    async def cancel(self, *, task_id: str, event_id: str) -> dict[str, Any]: ...

    async def sync(self, *, task_id: str, sync_token: str | None = None) -> dict[str, Any]: ...


class LocalCalendarProvider:
    name = "local"

    def __init__(self, store: CalendarStore) -> None:
        self.store = store

    async def list(
        self, *, task_id: str, start_at: datetime, end_at: datetime, query: str | None = None
    ) -> list[ProviderEvent]:
        del task_id
        return [
            self._event(item)
            for item in self.store.search(query=query, start_at=start_at, end_at=end_at, limit=500)
        ]

    async def get(self, *, task_id: str, event_id: str) -> ProviderEvent:
        del task_id
        return self._event(self.store.get(event_id))

    async def free_busy(
        self, *, task_id: str, start_at: datetime, end_at: datetime
    ) -> dict[str, Any]:
        del task_id
        return self.store.free_busy(start_at=start_at, end_at=end_at)

    async def create(self, *, task_id: str, event: CalendarEventCreate) -> ProviderEvent:
        created = self.store.create(event)
        return await self.get(task_id=task_id, event_id=created.event_id)

    async def update(
        self, *, task_id: str, event_id: str, update: CalendarEventUpdate
    ) -> ProviderEvent:
        self.store.update(event_id, update)
        return await self.get(task_id=task_id, event_id=event_id)

    async def cancel(self, *, task_id: str, event_id: str) -> dict[str, Any]:
        del task_id
        return self.store.cancel(event_id).model_dump(mode="json")

    async def sync(self, *, task_id: str, sync_token: str | None = None) -> dict[str, Any]:
        del task_id, sync_token
        return {"provider": "local", "changed": 0, "next_sync_token": None}

    @staticmethod
    def _event(item: Any) -> ProviderEvent:
        recurrence = item.recurrence
        return ProviderEvent(
            provider="local",
            external_event_id=item.event_id,
            title=item.title,
            start_at=item.start_at,
            end_at=item.end_at,
            timezone=item.timezone,
            location=item.location,
            description=item.description,
            status=item.status.value,
            recurrence=[str(recurrence)] if recurrence else [],
            attendees=item.attendees,
            reminders=item.reminders,
        )


class GoogleCalendarProvider:
    name = "google"

    def __init__(
        self,
        worker: BrowserWorkerClient,
        *,
        refresh_credential_id: str,
        client_id_credential_id: str,
        client_secret_credential_id: str,
        calendar_id: str = "primary",
    ) -> None:
        self.worker = worker
        self.refresh_credential_id = refresh_credential_id
        self.client_id_credential_id = client_id_credential_id
        self.client_secret_credential_id = client_secret_credential_id
        self.calendar_id = calendar_id

    async def _request(
        self,
        *,
        task_id: str,
        operation: str,
        event_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = await self.worker.google_calendar_request(
            refresh_credential_id=self.refresh_credential_id,
            client_id_credential_id=self.client_id_credential_id,
            client_secret_credential_id=self.client_secret_credential_id,
            task_id=task_id,
            operation=operation,
            calendar_id=self.calendar_id,
            event_id=event_id,
            payload=payload,
        )
        return dict(result.get("data") or {})

    async def list(
        self, *, task_id: str, start_at: datetime, end_at: datetime, query: str | None = None
    ) -> list[ProviderEvent]:
        payload: dict[str, Any] = {
            "timeMin": start_at.isoformat(),
            "timeMax": end_at.isoformat(),
            "singleEvents": True,
            "orderBy": "startTime",
            "maxResults": 500,
        }
        if query:
            payload["q"] = query
        items: list[dict[str, Any]] = []
        for _ in range(10):
            data = await self._request(task_id=task_id, operation="list", payload=payload)
            items.extend(data.get("items", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
            payload["pageToken"] = page_token
        return [self._event(item) for item in items]

    async def get(self, *, task_id: str, event_id: str) -> ProviderEvent:
        return self._event(await self._request(task_id=task_id, operation="get", event_id=event_id))

    async def free_busy(
        self, *, task_id: str, start_at: datetime, end_at: datetime
    ) -> dict[str, Any]:
        return await self._request(
            task_id=task_id,
            operation="free_busy",
            payload={"timeMin": start_at.isoformat(), "timeMax": end_at.isoformat()},
        )

    async def create(self, *, task_id: str, event: CalendarEventCreate) -> ProviderEvent:
        data = await self._request(
            task_id=task_id, operation="create", payload=self._payload(event)
        )
        return self._event(data)

    async def update(
        self, *, task_id: str, event_id: str, update: CalendarEventUpdate
    ) -> ProviderEvent:
        data = await self._request(
            task_id=task_id,
            operation="update",
            event_id=event_id,
            payload=self._update_payload(update),
        )
        return self._event(data)

    async def cancel(self, *, task_id: str, event_id: str) -> dict[str, Any]:
        return await self._request(task_id=task_id, operation="cancel", event_id=event_id)

    async def sync(self, *, task_id: str, sync_token: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"singleEvents": False, "maxResults": 500}
        if sync_token:
            payload["syncToken"] = sync_token
        events: list[dict[str, Any]] = []
        next_sync_token: str | None = None
        for _ in range(20):
            data = await self._request(task_id=task_id, operation="list", payload=payload)
            events.extend(data.get("items", []))
            next_sync_token = data.get("nextSyncToken") or next_sync_token
            page_token = data.get("nextPageToken")
            if not page_token:
                break
            payload["pageToken"] = page_token
        return {
            "provider": self.name,
            "events": [self._event(item).model_dump(mode="json") for item in events],
            "next_sync_token": next_sync_token,
        }

    @staticmethod
    def _payload(event: CalendarEventCreate) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "summary": event.title,
            "start": {"dateTime": event.start_at.isoformat(), "timeZone": event.timezone},
            "end": {"dateTime": event.end_at.isoformat(), "timeZone": event.timezone},
            "location": event.location,
            "description": event.description,
            "attendees": [{"email": item} for item in event.attendees],
            "reminders": {
                "useDefault": not bool(event.reminders),
                "overrides": [
                    {"method": "popup", "minutes": minutes} for minutes in event.reminders
                ],
            },
        }
        if event.recurrence:
            rule = event.recurrence
            components = [
                f"FREQ={rule.frequency.value.upper()}",
                f"INTERVAL={rule.interval}",
            ]
            if rule.count:
                components.append(f"COUNT={rule.count}")
            if rule.until:
                components.append(f"UNTIL={rule.until.strftime('%Y%m%dT%H%M%SZ')}")
            payload["recurrence"] = ["RRULE:" + ";".join(components)]
        return payload

    @staticmethod
    def _update_payload(update: CalendarEventUpdate) -> dict[str, Any]:
        values = update.model_dump(exclude_unset=True)
        payload: dict[str, Any] = {}
        if "title" in values:
            payload["summary"] = values["title"]
        if "start_at" in values:
            payload["start"] = {"dateTime": values["start_at"].isoformat()}
        if "end_at" in values:
            payload["end"] = {"dateTime": values["end_at"].isoformat()}
        for name in ("location", "description"):
            if name in values:
                payload[name] = values[name]
        if "attendees" in values:
            payload["attendees"] = [{"email": item} for item in values["attendees"] or []]
        if "reminders" in values:
            reminders = values["reminders"] or []
            payload["reminders"] = {
                "useDefault": not bool(reminders),
                "overrides": [{"method": "popup", "minutes": minutes} for minutes in reminders],
            }
        if "recurrence" in values:
            rule = values["recurrence"]
            if rule is None:
                payload["recurrence"] = []
            else:
                components = [
                    f"FREQ={rule.frequency.value.upper()}",
                    f"INTERVAL={rule.interval}",
                ]
                if rule.count:
                    components.append(f"COUNT={rule.count}")
                if rule.until:
                    components.append(f"UNTIL={rule.until.strftime('%Y%m%dT%H%M%SZ')}")
                payload["recurrence"] = ["RRULE:" + ";".join(components)]
        return payload

    @staticmethod
    def _event(value: dict[str, Any]) -> ProviderEvent:
        start = value.get("start") or {}
        end = value.get("end") or {}
        reminders = value.get("reminders") or {}
        return ProviderEvent(
            provider="google",
            external_event_id=str(value.get("id") or ""),
            version=value.get("etag") or value.get("updated"),
            title=str(value.get("summary") or "(no title)"),
            start_at=str(start.get("dateTime") or start.get("date")),
            end_at=str(end.get("dateTime") or end.get("date")),
            timezone=str(start.get("timeZone") or "Asia/Tokyo"),
            location=value.get("location"),
            description=str(value.get("description") or ""),
            status=str(value.get("status") or "confirmed"),
            recurrence=[str(item) for item in value.get("recurrence") or []],
            attendees=[
                str(item.get("email")) for item in value.get("attendees") or [] if item.get("email")
            ],
            reminders=[
                int(item["minutes"])
                for item in reminders.get("overrides") or []
                if "minutes" in item
            ],
            raw=value,
        )
