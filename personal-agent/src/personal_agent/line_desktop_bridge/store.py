from __future__ import annotations

import hashlib
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class LineDesktopBridgeStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS conversations (
                    conversation_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS send_actions (
                    idempotency_key TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    external_message_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def remember_conversation(self, conversation_id: str, title: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO conversations(conversation_id, title, last_seen_at) VALUES (?, ?, ?) "
                "ON CONFLICT(conversation_id) DO UPDATE SET title=excluded.title, "
                "last_seen_at=excluded.last_seen_at",
                (conversation_id, title, utc_now()),
            )

    def conversation_title(self, conversation_id: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT title FROM conversations WHERE conversation_id=?", (conversation_id,)
            ).fetchone()
        if row is None:
            raise KeyError(conversation_id)
        return str(row["title"])

    def claim_send(
        self, idempotency_key: str, *, conversation_id: str, text: str
    ) -> dict[str, Any]:
        request_hash = hashlib.sha256(f"{conversation_id}\0{text}".encode()).hexdigest()
        now = utc_now()
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM send_actions WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if row is not None:
                if row["request_hash"] != request_hash:
                    raise ValueError("Idempotency key was reused with different content")
                return {**dict(row), "claimed": False}
            connection.execute(
                "INSERT INTO send_actions(idempotency_key, request_hash, status, created_at, "
                "updated_at) VALUES (?, ?, 'executing', ?, ?)",
                (idempotency_key, request_hash, now, now),
            )
        return {
            "idempotency_key": idempotency_key,
            "request_hash": request_hash,
            "status": "executing",
            "external_message_id": None,
            "claimed": True,
        }

    def finish_send(
        self, idempotency_key: str, *, status: str, external_message_id: str | None = None
    ) -> None:
        if status not in {"ok", "submitted_unknown", "rejected"}:
            raise ValueError("Invalid send state")
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE send_actions SET status=?, external_message_id=?, updated_at=? "
                "WHERE idempotency_key=? AND status='executing'",
                (status, external_message_id, utc_now(), idempotency_key),
            )
        if cursor.rowcount != 1:
            raise KeyError(idempotency_key)
