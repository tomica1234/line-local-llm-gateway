from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from zoneinfo import ZoneInfo

from .storage import Storage, utc_now
from .types import Channel, RiskLevel, TaskState


class Attention(StrEnum):
    IGNORE = "IGNORE"
    REMEMBER = "REMEMBER"
    DAILY_DIGEST = "DAILY_DIGEST"
    MENTION_LATER = "MENTION_LATER"
    NOTIFY_NOW = "NOTIFY_NOW"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    AUTO_ACT = "AUTO_ACT"


PROACTIVE_SCHEMA = """
CREATE TABLE IF NOT EXISTS opportunities (
    opportunity_id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    attention TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_event_ids_json TEXT NOT NULL,
    state TEXT NOT NULL,
    notified_task_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(category, evidence_event_ids_json)
);
"""

_PATTERNS: list[tuple[str, re.Pattern[str], Attention, float]] = [
    (
        "reply",
        re.compile(r"返信が必要|要返信|返事を待|reply required", re.I),
        Attention.ACTION_REQUIRED,
        0.92,
    ),
    (
        "refund",
        re.compile(r"返金待|返金されていない|refund pending", re.I),
        Attention.ACTION_REQUIRED,
        0.94,
    ),
    (
        "delivery",
        re.compile(r"配送遅延|未配送|delivery delay", re.I),
        Attention.NOTIFY_NOW,
        0.90,
    ),
    (
        "deadline",
        re.compile(r"期限.{0,8}(今日|明日|間近)|due (today|tomorrow)", re.I),
        Attention.NOTIFY_NOW,
        0.90,
    ),
    (
        "subscription",
        re.compile(r"使っていない.*サブスク|unused subscription", re.I),
        Attention.DAILY_DIGEST,
        0.82,
    ),
]


class ProactiveService:
    def __init__(self, storage: Storage, *, user_id: str = "primary", timezone: str = "Asia/Tokyo"):
        self.storage = storage
        self.user_id = user_id
        self.timezone = ZoneInfo(timezone)

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(PROACTIVE_SCHEMA)
        defaults = {
            "proactive_enabled": False,
            "proactive_categories": {item[0]: True for item in _PATTERNS},
            "proactive_quiet_hours": {"start": "22:00", "end": "07:00"},
            "proactive_frequency_minutes": 300,
        }
        for key, value in defaults.items():
            try:
                self.storage.get_setting(key)
            except KeyError:
                self.storage.set_setting(key, value)

    def settings(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.storage.get_setting("proactive_enabled")),
            "categories": self.storage.get_setting("proactive_categories"),
            "quiet_hours": self.storage.get_setting("proactive_quiet_hours"),
            "frequency_minutes": int(self.storage.get_setting("proactive_frequency_minutes")),
        }

    def update_settings(
        self,
        *,
        enabled: bool,
        categories: dict[str, bool],
        quiet_hours: dict[str, str],
        frequency_minutes: int = 300,
    ) -> dict[str, Any]:
        known = {item[0] for item in _PATTERNS}
        if not set(categories).issubset(known):
            raise ValueError("Unknown proactive category")
        for key in ("start", "end"):
            try:
                datetime.strptime(quiet_hours[key], "%H:%M")
            except (KeyError, ValueError) as exc:
                raise ValueError("Quiet hours must contain HH:MM start and end") from exc
        if not 5 <= frequency_minutes <= 1_440:
            raise ValueError("Proactive frequency must be between 5 and 1440 minutes")
        current = self.storage.get_setting("proactive_categories")
        merged = {name: categories.get(name, current.get(name, True)) for name in known}
        self.storage.set_setting("proactive_enabled", enabled)
        self.storage.set_setting("proactive_categories", merged)
        self.storage.set_setting("proactive_quiet_hours", quiet_hours)
        self.storage.set_setting("proactive_frequency_minutes", frequency_minutes)
        return self.settings()

    def scan(self, *, limit: int = 500) -> list[dict[str, Any]]:
        settings = self.settings()
        if not settings["enabled"]:
            return []
        created: list[dict[str, Any]] = []
        with self.storage.read_connection() as connection:
            events = connection.execute(
                "SELECT event_id, content FROM raw_events WHERE content != '' "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        quiet = self._in_quiet_hours(settings["quiet_hours"])
        for event in events:
            for category, pattern, attention, confidence in _PATTERNS:
                if not settings["categories"].get(category, True) or not pattern.search(
                    event["content"]
                ):
                    continue
                selected_attention = (
                    Attention.DAILY_DIGEST
                    if quiet and attention in {Attention.NOTIFY_NOW, Attention.ACTION_REQUIRED}
                    else attention
                )
                opportunity = self._insert(
                    category=category,
                    summary=event["content"][:500],
                    attention=selected_attention,
                    confidence=confidence,
                    evidence_event_id=event["event_id"],
                )
                if opportunity:
                    created.append(opportunity)
                    if selected_attention in {Attention.NOTIFY_NOW, Attention.ACTION_REQUIRED}:
                        opportunity["notified_task_id"] = self._notify(opportunity)
        return created

    def list(self, *, state: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            if state:
                rows = connection.execute(
                    "SELECT * FROM opportunities WHERE state=? ORDER BY created_at DESC LIMIT ?",
                    (state, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM opportunities ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [self._row(row) for row in rows]

    def resolve(self, opportunity_id: str) -> dict[str, Any]:
        with self.storage.transaction() as connection:
            existing = connection.execute(
                "SELECT notified_task_id FROM opportunities WHERE opportunity_id=? "
                "AND state='open'",
                (opportunity_id,),
            ).fetchone()
            if existing is None:
                raise KeyError(opportunity_id)
            cursor = connection.execute(
                "UPDATE opportunities SET state='resolved', updated_at=? "
                "WHERE opportunity_id=? AND state='open'",
                (utc_now(), opportunity_id),
            )
            connection.execute(
                "UPDATE scheduled_jobs SET status='cancelled', updated_at=? "
                "WHERE status='scheduled' AND "
                "json_extract(payload_json, '$.opportunity_id')=?",
                (utc_now(), opportunity_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(opportunity_id)
        if existing["notified_task_id"]:
            self.storage.update_task(
                existing["notified_task_id"],
                state=TaskState.COMPLETED,
                result={"opportunity_id": opportunity_id, "resolved": True},
                event_type="proactive_opportunity_resolved",
            )
        return next(item for item in self.list() if item["opportunity_id"] == opportunity_id)

    def _insert(
        self,
        *,
        category: str,
        summary: str,
        attention: Attention,
        confidence: float,
        evidence_event_id: str,
    ) -> dict[str, Any] | None:
        opportunity_id = str(uuid.uuid4())
        evidence = json.dumps([evidence_event_id])
        now = utc_now()
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO opportunities "
                "(opportunity_id, category, summary, attention, confidence, "
                "evidence_event_ids_json, state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)",
                (
                    opportunity_id,
                    category,
                    summary,
                    attention.value,
                    confidence,
                    evidence,
                    now,
                    now,
                ),
            )
            if not cursor.rowcount:
                return None
            row = connection.execute(
                "SELECT * FROM opportunities WHERE opportunity_id=?", (opportunity_id,)
            ).fetchone()
        return self._row(row)

    def briefing(self, *, period: str) -> dict[str, Any]:
        if period not in {"morning", "evening"}:
            raise ValueError("Briefing period must be morning or evening")
        now = datetime.now(self.timezone)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start.replace(hour=23, minute=59, second=59)
        with self.storage.read_connection() as connection:
            events = connection.execute(
                "SELECT event_id, title, start_at, end_at, location FROM calendar_events "
                "WHERE status != 'cancelled' AND start_at < ? AND end_at > ? "
                "ORDER BY start_at",
                (day_end.isoformat(), day_start.isoformat()),
            ).fetchall()
            raw_count = connection.execute(
                "SELECT COUNT(*) FROM raw_events WHERE timestamp >= ? AND timestamp <= ?",
                (day_start.astimezone(UTC).isoformat(), day_end.astimezone(UTC).isoformat()),
            ).fetchone()[0]
        opportunities = self.list(state="open", limit=100)
        return {
            "period": period,
            "date": now.date().isoformat(),
            "timezone": str(self.timezone),
            "calendar": [dict(row) for row in events],
            "open_opportunities": opportunities,
            "raw_event_count": raw_count,
            "generated_at": now.isoformat(),
        }

    def _notify(self, opportunity: dict[str, Any]) -> str:
        task = self.storage.create_task(
            user_id=self.user_id,
            goal=f"Proactive follow-up: {opportunity['summary']}",
            source=Channel.WEB,
            conversation_id="pwa-primary",
            risk_level=RiskLevel.R0,
        )
        self.storage.update_task(
            task.task_id,
            state=TaskState.WAITING_EXTERNAL,
            result={
                "opportunity_id": opportunity["opportunity_id"],
                "attention": opportunity["attention"],
            },
            event_type="proactive_follow_up_waiting",
        )
        self.storage.create_scheduled_job(
            task_id=task.task_id,
            kind="follow_up",
            run_at=datetime.now(UTC).isoformat(),
            payload={
                "label": opportunity["summary"],
                "opportunity_id": opportunity["opportunity_id"],
                "recurrence": {
                    "frequency": "daily",
                    "interval": 1,
                    "count": 30,
                    "until": None,
                },
            },
        )
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE opportunities SET notified_task_id=?, updated_at=? WHERE opportunity_id=?",
                (task.task_id, utc_now(), opportunity["opportunity_id"]),
            )
        return task.task_id

    def _in_quiet_hours(self, value: dict[str, str]) -> bool:
        now = datetime.now(self.timezone).time()
        start = datetime.strptime(value["start"], "%H:%M").time()
        end = datetime.strptime(value["end"], "%H:%M").time()
        return start <= now < end if start < end else now >= start or now < end

    @staticmethod
    def _row(row: Any) -> dict[str, Any]:
        result = dict(row)
        result["evidence_event_ids"] = json.loads(result.pop("evidence_event_ids_json"))
        return result
