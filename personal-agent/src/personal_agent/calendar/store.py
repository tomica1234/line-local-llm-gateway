from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from ..memory.sanitizer import sanitize_text
from ..migrations import Migration, add_column, apply_migrations
from ..storage import Storage, utc_now
from .models import CalendarEventCreate, CalendarEventRecord, CalendarEventUpdate

CALENDAR_SCHEMA = """
CREATE TABLE IF NOT EXISTS calendar_events (
    event_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    start_at TEXT NOT NULL,
    end_at TEXT NOT NULL,
    timezone TEXT NOT NULL,
    location TEXT,
    description TEXT NOT NULL,
    status TEXT NOT NULL,
    recurrence_json TEXT,
    attendees_json TEXT NOT NULL DEFAULT '[]',
    reminders_json TEXT NOT NULL DEFAULT '[]',
    linked_economic_intent_id TEXT,
    source_reference TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_calendar_interval
ON calendar_events(status, start_at, end_at);
CREATE VIRTUAL TABLE IF NOT EXISTS calendar_fts USING fts5(
    event_id UNINDEXED, title, location, description, tokenize='trigram'
);
CREATE TABLE IF NOT EXISTS calendar_provider_state (
    provider TEXT PRIMARY KEY,
    sync_token TEXT,
    status TEXT NOT NULL,
    last_synced_at TEXT,
    last_error TEXT,
    updated_at TEXT NOT NULL
);
"""


def _calendar_v2(connection: Any) -> None:
    add_column(connection, "calendar_events", "attendees_json TEXT NOT NULL DEFAULT '[]'")
    add_column(connection, "calendar_events", "reminders_json TEXT NOT NULL DEFAULT '[]'")
    add_column(connection, "calendar_events", "provider TEXT NOT NULL DEFAULT 'local'")
    add_column(connection, "calendar_events", "external_event_id TEXT")
    add_column(connection, "calendar_events", "external_version TEXT")
    add_column(connection, "calendar_events", "last_synced_at TEXT")
    add_column(connection, "calendar_events", "sync_state TEXT NOT NULL DEFAULT 'local_only'")
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_calendar_provider_external "
        "ON calendar_events(provider, external_event_id) WHERE external_event_id IS NOT NULL"
    )


CALENDAR_MIGRATIONS = (Migration(2, "provider-sync-and-approval-fields", _calendar_v2),)


class CalendarConflict(ValueError):
    def __init__(self, conflicts: list[CalendarEventRecord]):
        super().__init__("Calendar event conflicts with an existing event")
        self.conflicts = conflicts


class CalendarStore:
    def __init__(self, storage: Storage, *, default_timezone: str = "Asia/Tokyo"):
        self.storage = storage
        self.default_timezone = ZoneInfo(default_timezone)

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(CALENDAR_SCHEMA)
            apply_migrations(connection, component="calendar", migrations=CALENDAR_MIGRATIONS)

    def search(
        self,
        *,
        query: str | None,
        start_at: datetime,
        end_at: datetime,
        limit: int = 100,
    ) -> list[CalendarEventRecord]:
        self._validate_interval(start_at, end_at)
        with self.storage.read_connection() as connection:
            if query and query.strip():
                escaped = query.strip().replace('"', '""')
                rows = connection.execute(
                    "SELECT e.* FROM calendar_fts f JOIN calendar_events e USING(event_id) "
                    "WHERE calendar_fts MATCH ? AND e.status != 'cancelled' "
                    "AND e.start_at < ? AND e.end_at > ? ORDER BY e.start_at LIMIT ?",
                    (f'"{escaped}"', end_at.isoformat(), start_at.isoformat(), limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM calendar_events WHERE status != 'cancelled' "
                    "AND start_at < ? AND end_at > ? ORDER BY start_at LIMIT ?",
                    (end_at.isoformat(), start_at.isoformat(), limit),
                ).fetchall()
        return [self._record(row) for row in rows]

    def free_busy(self, *, start_at: datetime, end_at: datetime) -> dict[str, list[dict[str, str]]]:
        events = self.search(query=None, start_at=start_at, end_at=end_at, limit=1_000)
        busy = [
            {"event_id": item.event_id, "start_at": item.start_at, "end_at": item.end_at}
            for item in events
            if item.status in {"confirmed", "tentative"}
        ]
        return {"busy": busy}

    def conflicts(
        self,
        *,
        start_at: datetime,
        end_at: datetime,
        exclude_event_id: str | None = None,
    ) -> list[CalendarEventRecord]:
        events = self.search(query=None, start_at=start_at, end_at=end_at, limit=1_000)
        return [item for item in events if item.event_id != exclude_event_id]

    def create(self, event: CalendarEventCreate) -> CalendarEventRecord:
        conflicts = self.conflicts(start_at=event.start_at, end_at=event.end_at)
        if event.fail_on_conflict and conflicts:
            raise CalendarConflict(conflicts)
        safe_title, _ = sanitize_text(event.title)
        safe_description, _ = sanitize_text(event.description)
        safe_location = sanitize_text(event.location)[0] if event.location else None
        event_id = str(uuid.uuid4())
        now = utc_now()
        recurrence = event.recurrence.model_dump(mode="json") if event.recurrence else None
        with self.storage.transaction() as connection:
            duplicate = connection.execute(
                "SELECT event_id FROM calendar_events WHERE status != 'cancelled' "
                "AND title = ? AND start_at = ? AND end_at = ?",
                (safe_title, event.start_at.isoformat(), event.end_at.isoformat()),
            ).fetchone()
            if duplicate:
                raise ValueError("Duplicate calendar event")
            connection.execute(
                "INSERT INTO calendar_events "
                "(event_id, title, start_at, end_at, timezone, location, description, status, "
                "recurrence_json, attendees_json, reminders_json, linked_economic_intent_id, "
                "source_reference, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    safe_title,
                    event.start_at.isoformat(),
                    event.end_at.isoformat(),
                    event.timezone,
                    safe_location,
                    safe_description,
                    event.status.value,
                    json.dumps(recurrence) if recurrence else None,
                    json.dumps(event.attendees, ensure_ascii=False),
                    json.dumps(event.reminders),
                    event.linked_economic_intent_id,
                    event.source_reference,
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO calendar_fts(event_id, title, location, description) "
                "VALUES (?, ?, ?, ?)",
                (event_id, safe_title, safe_location or "", safe_description),
            )
        return self.get(event_id)

    def get(self, event_id: str) -> CalendarEventRecord:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM calendar_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise KeyError(event_id)
        return self._record(row)

    def update(self, event_id: str, update: CalendarEventUpdate) -> CalendarEventRecord:
        current = self.get(event_id)
        if current.status == "cancelled":
            raise ValueError("Cancelled event cannot be updated")
        start_at = update.start_at or datetime.fromisoformat(current.start_at)
        end_at = update.end_at or datetime.fromisoformat(current.end_at)
        self._validate_interval(start_at, end_at)
        conflicts = self.conflicts(start_at=start_at, end_at=end_at, exclude_event_id=event_id)
        if update.fail_on_conflict and conflicts:
            raise CalendarConflict(conflicts)
        title = sanitize_text(update.title)[0] if update.title is not None else current.title
        description = (
            sanitize_text(update.description)[0]
            if update.description is not None
            else current.description
        )
        location = (
            sanitize_text(update.location)[0] if update.location is not None else current.location
        )
        recurrence = (
            update.recurrence.model_dump(mode="json")
            if update.recurrence is not None
            else current.recurrence
        )
        attendees = update.attendees if update.attendees is not None else current.attendees
        reminders = update.reminders if update.reminders is not None else current.reminders
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE calendar_events SET title=?, start_at=?, end_at=?, location=?, "
                "description=?, recurrence_json=?, attendees_json=?, reminders_json=?, "
                "sync_state=CASE WHEN provider='local' THEN sync_state ELSE 'pending_update' END, "
                "updated_at=? WHERE event_id=?",
                (
                    title,
                    start_at.isoformat(),
                    end_at.isoformat(),
                    location,
                    description,
                    json.dumps(recurrence) if recurrence else None,
                    json.dumps(attendees, ensure_ascii=False),
                    json.dumps(reminders),
                    utc_now(),
                    event_id,
                ),
            )
            connection.execute("DELETE FROM calendar_fts WHERE event_id = ?", (event_id,))
            connection.execute(
                "INSERT INTO calendar_fts(event_id, title, location, description) "
                "VALUES (?, ?, ?, ?)",
                (event_id, title, location or "", description),
            )
        return self.get(event_id)

    def cancel(self, event_id: str) -> CalendarEventRecord:
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "UPDATE calendar_events SET status='cancelled', updated_at=? "
                "WHERE event_id=? AND status != 'cancelled'",
                (utc_now(), event_id),
            )
            connection.execute("DELETE FROM calendar_fts WHERE event_id = ?", (event_id,))
        if cursor.rowcount != 1:
            current = self.get(event_id)
            if current.status != "cancelled":
                raise ValueError("Calendar event could not be cancelled")
        return self.get(event_id)

    def provider_state(self, provider: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM calendar_provider_state WHERE provider=?", (provider,)
            ).fetchone()
        return (
            dict(row)
            if row
            else {
                "provider": provider,
                "sync_token": None,
                "status": "not_synced",
                "last_synced_at": None,
                "last_error": None,
            }
        )

    def record_provider_state(
        self,
        provider: str,
        *,
        status: str,
        sync_token: str | None = None,
        error: str | None = None,
    ) -> None:
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO calendar_provider_state(provider, sync_token, status, "
                "last_synced_at, last_error, updated_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(provider) DO UPDATE SET sync_token=COALESCE(excluded.sync_token, "
                "calendar_provider_state.sync_token), status=excluded.status, "
                "last_synced_at=excluded.last_synced_at, last_error=excluded.last_error, "
                "updated_at=excluded.updated_at",
                (provider, sync_token, status, now if status == "ok" else None, error, now),
            )

    def upsert_provider_event(self, value: dict[str, Any]) -> dict[str, Any]:
        provider = str(value["provider"])
        external_id = str(value["external_event_id"])
        version = value.get("version")
        now = utc_now()
        with self.storage.transaction() as connection:
            current = connection.execute(
                "SELECT * FROM calendar_events WHERE provider=? AND external_event_id=?",
                (provider, external_id),
            ).fetchone()
            if current and current["external_version"] == version:
                return {"state": "unchanged", "event_id": current["event_id"]}
            if current and current["sync_state"] in {"pending_update", "pending_cancel"}:
                connection.execute(
                    "UPDATE calendar_events SET sync_state='conflict', updated_at=? "
                    "WHERE event_id=?",
                    (now, current["event_id"]),
                )
                return {"state": "conflict", "event_id": current["event_id"]}
            event_id = str(current["event_id"]) if current else str(uuid.uuid4())
            safe_title = sanitize_text(str(value.get("title") or "(no title)"))[0]
            safe_description = sanitize_text(str(value.get("description") or ""))[0]
            safe_location = (
                sanitize_text(str(value["location"]))[0] if value.get("location") else None
            )
            recurrence = value.get("recurrence") or None
            connection.execute(
                "INSERT INTO calendar_events(event_id, title, start_at, end_at, timezone, "
                "location, description, status, recurrence_json, attendees_json, reminders_json, "
                "provider, external_event_id, external_version, last_synced_at, sync_state, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "'synced', ?, ?) ON CONFLICT(event_id) DO UPDATE SET title=excluded.title, "
                "start_at=excluded.start_at, end_at=excluded.end_at, timezone=excluded.timezone, "
                "location=excluded.location, description=excluded.description, "
                "status=excluded.status, recurrence_json=excluded.recurrence_json, "
                "attendees_json=excluded.attendees_json, reminders_json=excluded.reminders_json, "
                "external_version=excluded.external_version, "
                "last_synced_at=excluded.last_synced_at, "
                "sync_state='synced', updated_at=excluded.updated_at",
                (
                    event_id,
                    safe_title,
                    value["start_at"],
                    value["end_at"],
                    value.get("timezone") or "Asia/Tokyo",
                    safe_location,
                    safe_description,
                    (
                        "cancelled"
                        if value.get("status") == "cancelled"
                        else value.get("status", "confirmed")
                    ),
                    json.dumps(recurrence, ensure_ascii=False) if recurrence else None,
                    json.dumps(value.get("attendees") or [], ensure_ascii=False),
                    json.dumps(value.get("reminders") or []),
                    provider,
                    external_id,
                    version,
                    now,
                    now,
                    now,
                ),
            )
            connection.execute("DELETE FROM calendar_fts WHERE event_id=?", (event_id,))
            if value.get("status") != "cancelled":
                connection.execute(
                    "INSERT INTO calendar_fts(event_id, title, location, description) "
                    "VALUES (?, ?, ?, ?)",
                    (event_id, safe_title, safe_location or "", safe_description),
                )
        return {"state": "created" if current is None else "updated", "event_id": event_id}

    @staticmethod
    def _validate_interval(start_at: datetime, end_at: datetime) -> None:
        if start_at.tzinfo is None or end_at.tzinfo is None:
            raise ValueError("Calendar timestamps must include timezone offsets")
        if end_at <= start_at:
            raise ValueError("Calendar interval end must be after start")

    @staticmethod
    def _record(row: Any) -> CalendarEventRecord:
        return CalendarEventRecord(
            event_id=row["event_id"],
            title=row["title"],
            start_at=row["start_at"],
            end_at=row["end_at"],
            timezone=row["timezone"],
            location=row["location"],
            description=row["description"],
            status=row["status"],
            recurrence=json.loads(row["recurrence_json"]) if row["recurrence_json"] else None,
            attendees=json.loads(row["attendees_json"]) if row["attendees_json"] else [],
            reminders=json.loads(row["reminders_json"]) if row["reminders_json"] else [],
            linked_economic_intent_id=row["linked_economic_intent_id"],
            source_reference=row["source_reference"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            provider=row["provider"],
            external_event_id=row["external_event_id"],
            external_version=row["external_version"],
            last_synced_at=row["last_synced_at"],
            sync_state=row["sync_state"],
        )
