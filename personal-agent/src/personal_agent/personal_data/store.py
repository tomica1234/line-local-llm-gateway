from __future__ import annotations

import json
import uuid
from datetime import date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from ..storage import Storage, utc_now
from .models import (
    DiaryCreate,
    DiaryEntry,
    PersonalTodo,
    PersonalTodoCreate,
    PersonalTodoUpdate,
    TodoStatus,
)

PERSONAL_DATA_SCHEMA = """
CREATE TABLE IF NOT EXISTS personal_todos (
    todo_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    todo_type TEXT NOT NULL,
    title TEXT NOT NULL,
    due_at TEXT,
    remind_at TEXT,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_personal_todos_user_status_due
ON personal_todos(user_id, status, due_at, created_at);

CREATE TABLE IF NOT EXISTS diary_entries (
    diary_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    business_date TEXT NOT NULL,
    summary TEXT NOT NULL,
    mood INTEGER,
    good TEXT,
    bad TEXT,
    learned TEXT,
    tomorrow TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_diary_entries_user_date
ON diary_entries(user_id, business_date DESC, created_at DESC);
"""


def business_date(
    now: datetime | None = None,
    *,
    timezone: str | ZoneInfo = "Asia/Tokyo",
) -> date:
    zone = timezone if isinstance(timezone, ZoneInfo) else ZoneInfo(timezone)
    current = now.astimezone(zone) if now is not None else datetime.now(zone)
    if time(0, 0) <= current.time() < time(4, 0):
        return current.date() - timedelta(days=1)
    return current.date()


class PersonalDataStore:
    """Structured personal Todo/Diary storage, separate from Agent execution tasks."""

    def __init__(self, storage: Storage, *, user_id: str, timezone: str) -> None:
        self.storage = storage
        self.user_id = user_id
        self.timezone = timezone

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(PERSONAL_DATA_SCHEMA)

    def create_todo(self, value: PersonalTodoCreate) -> PersonalTodo:
        todo_id = str(uuid.uuid4())
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO personal_todos "
                "(todo_id, user_id, todo_type, title, due_at, remind_at, priority, status, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)",
                (
                    todo_id,
                    self.user_id,
                    value.todo_type.value,
                    value.title,
                    value.due_at.isoformat() if value.due_at else None,
                    value.remind_at.isoformat() if value.remind_at else None,
                    value.priority.value,
                    now,
                    now,
                ),
            )
        return self.get_todo(todo_id)

    def get_todo(self, todo_id: str) -> PersonalTodo:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM personal_todos WHERE todo_id=? AND user_id=?",
                (todo_id, self.user_id),
            ).fetchone()
        if row is None:
            raise KeyError(todo_id)
        return PersonalTodo.model_validate(dict(row))

    def list_todos(
        self,
        *,
        status: TodoStatus | None = TodoStatus.OPEN,
        limit: int = 100,
    ) -> list[PersonalTodo]:
        query = "SELECT * FROM personal_todos WHERE user_id=?"
        parameters: list[Any] = [self.user_id]
        if status is not None:
            query += " AND status=?"
            parameters.append(status.value)
        query += " ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END, "
        query += "due_at IS NULL, due_at, created_at LIMIT ?"
        parameters.append(limit)
        with self.storage.read_connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [PersonalTodo.model_validate(dict(row)) for row in rows]

    def complete_todo(self, todo_id: str) -> PersonalTodo:
        now = utc_now()
        with self.storage.transaction() as connection:
            row = connection.execute(
                "SELECT status FROM personal_todos WHERE todo_id=? AND user_id=?",
                (todo_id, self.user_id),
            ).fetchone()
            if row is None:
                raise KeyError(todo_id)
            if row["status"] != TodoStatus.COMPLETED.value:
                connection.execute(
                    "UPDATE personal_todos SET status='completed', completed_at=?, updated_at=? "
                    "WHERE todo_id=? AND user_id=?",
                    (now, now, todo_id, self.user_id),
                )
        return self.get_todo(todo_id)

    def update_todo(self, todo_id: str, update: PersonalTodoUpdate) -> PersonalTodo:
        current = self.get_todo(todo_id)
        values = update.model_dump(exclude_unset=True, mode="json")
        column_names = {"todo_type", "title", "due_at", "remind_at", "priority"}
        assignments: list[str] = []
        parameters: list[Any] = []
        for name, value in values.items():
            if name not in column_names:
                continue
            assignments.append(f"{name}=?")
            parameters.append(value)
        if not assignments:
            return current
        assignments.append("updated_at=?")
        parameters.extend([utc_now(), todo_id, self.user_id])
        with self.storage.transaction() as connection:
            connection.execute(
                f"UPDATE personal_todos SET {', '.join(assignments)} "
                "WHERE todo_id=? AND user_id=?",
                parameters,
            )
        return self.get_todo(todo_id)

    def create_diary(self, value: DiaryCreate) -> DiaryEntry:
        diary_id = str(uuid.uuid4())
        entry_date = value.date or business_date(timezone=self.timezone)
        now = utc_now()
        tags = list(dict.fromkeys(tag.strip() for tag in value.tags if tag.strip()))
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO diary_entries "
                "(diary_id, user_id, business_date, summary, mood, good, bad, learned, "
                "tomorrow, tags_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    diary_id,
                    self.user_id,
                    entry_date.isoformat(),
                    value.summary,
                    value.mood,
                    value.good,
                    value.bad,
                    value.learned,
                    value.tomorrow,
                    json.dumps(tags, ensure_ascii=False),
                    now,
                    now,
                ),
            )
        return self.get_diary(diary_id)

    def get_diary(self, diary_id: str) -> DiaryEntry:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM diary_entries WHERE diary_id=? AND user_id=?",
                (diary_id, self.user_id),
            ).fetchone()
        if row is None:
            raise KeyError(diary_id)
        return self._diary_from_row(row)

    def read_diary(self, entry_date: date | None = None) -> list[DiaryEntry]:
        selected = entry_date or business_date(timezone=self.timezone)
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM diary_entries WHERE user_id=? AND business_date=? "
                "ORDER BY created_at",
                (self.user_id, selected.isoformat()),
            ).fetchall()
        return [self._diary_from_row(row) for row in rows]

    def search_diary(self, keyword: str, *, limit: int = 50) -> list[DiaryEntry]:
        pattern = f"%{keyword}%"
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM diary_entries WHERE user_id=? AND "
                "(summary LIKE ? OR good LIKE ? OR bad LIKE ? OR learned LIKE ? "
                "OR tomorrow LIKE ? OR tags_json LIKE ?) "
                "ORDER BY business_date DESC, created_at DESC LIMIT ?",
                (self.user_id, pattern, pattern, pattern, pattern, pattern, pattern, limit),
            ).fetchall()
        return [self._diary_from_row(row) for row in rows]

    @staticmethod
    def _diary_from_row(row: Any) -> DiaryEntry:
        value = dict(row)
        value["date"] = value.pop("business_date")
        value["tags"] = json.loads(value.pop("tags_json"))
        return DiaryEntry.model_validate(value)
