from __future__ import annotations

import json
import uuid
from typing import Any

from ..memory.sanitizer import sanitize_payload, sanitize_text
from ..storage import Storage, utc_now
from .models import (
    CommunicationSearchHit,
    CommunicationSource,
    DraftRecord,
    NormalizedMessageCreate,
)

COMMUNICATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS communication_messages (
    message_id TEXT NOT NULL,
    source TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    thread_id TEXT,
    sender_entity_id TEXT,
    timestamp TEXT NOT NULL,
    text TEXT NOT NULL,
    attachments_json TEXT NOT NULL,
    reply_to TEXT,
    permissions_json TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(source, message_id)
);
CREATE INDEX IF NOT EXISTS idx_comm_thread
ON communication_messages(source, conversation_id, thread_id, timestamp);
CREATE VIRTUAL TABLE IF NOT EXISTS communication_fts USING fts5(
    message_key UNINDEXED, text, tokenize='trigram'
);
CREATE TABLE IF NOT EXISTS communication_drafts (
    draft_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    source TEXT NOT NULL,
    recipient_entity_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    thread_id TEXT,
    reply_to TEXT,
    state TEXT NOT NULL,
    external_message_id TEXT,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS connectors (
    provider TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,
    scopes_json TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class CommunicationStore:
    def __init__(self, storage: Storage):
        self.storage = storage

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(COMMUNICATION_SCHEMA)
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(communication_drafts)").fetchall()
            }
            if "subject" not in columns:
                connection.execute(
                    "ALTER TABLE communication_drafts ADD COLUMN subject TEXT NOT NULL DEFAULT ''"
                )

    def ingest(self, message: NormalizedMessageCreate) -> bool:
        text, _ = sanitize_text(message.text)
        attachments, _ = sanitize_payload(
            [item.model_dump(mode="json") for item in message.attachments]
        )
        key = f"{message.source.value}:{message.message_id}"
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO communication_messages "
                "(message_id, source, conversation_id, thread_id, sender_entity_id, "
                "timestamp, text, attachments_json, reply_to, permissions_json, "
                "source_reference, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    message.message_id,
                    message.source.value,
                    message.conversation_id,
                    message.thread_id,
                    message.sender_entity_id,
                    message.timestamp,
                    text,
                    json.dumps(attachments, ensure_ascii=False),
                    message.reply_to,
                    json.dumps(message.permissions),
                    message.source_reference,
                    utc_now(),
                ),
            )
            if cursor.rowcount:
                connection.execute(
                    "INSERT INTO communication_fts(message_key, text) VALUES (?, ?)",
                    (key, text),
                )
            return cursor.rowcount == 1

    def search(self, query: str, *, limit: int = 50) -> list[CommunicationSearchHit]:
        normalized = query.strip()
        if not normalized:
            return []
        tokens = [token for token in normalized.split() if token]
        match = " OR ".join(f'"{token.replace(chr(34), chr(34) * 2)}"' for token in tokens)
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT m.* FROM communication_fts f JOIN communication_messages m "
                "ON f.message_key = m.source || ':' || m.message_id "
                "WHERE communication_fts MATCH ? ORDER BY bm25(communication_fts) LIMIT ?",
                (match, limit),
            ).fetchall()
        return [self._message(row) for row in rows]

    def read(self, *, source: CommunicationSource, message_id: str) -> CommunicationSearchHit:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM communication_messages WHERE source = ? AND message_id = ?",
                (source.value, message_id),
            ).fetchone()
        if row is None:
            raise KeyError(message_id)
        return self._message(row)

    def thread(
        self,
        *,
        source: CommunicationSource,
        conversation_id: str,
        thread_id: str | None,
        limit: int = 100,
    ) -> list[CommunicationSearchHit]:
        with self.storage.read_connection() as connection:
            if thread_id is None:
                rows = connection.execute(
                    "SELECT * FROM communication_messages WHERE source = ? "
                    "AND conversation_id = ? AND thread_id IS NULL "
                    "ORDER BY timestamp LIMIT ?",
                    (source.value, conversation_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM communication_messages WHERE source = ? "
                    "AND conversation_id = ? AND thread_id = ? ORDER BY timestamp LIMIT ?",
                    (source.value, conversation_id, thread_id, limit),
                ).fetchall()
        return [self._message(row) for row in rows]

    def create_draft(
        self,
        *,
        task_id: str,
        source: CommunicationSource,
        recipient_entity_id: str,
        conversation_id: str,
        subject: str,
        text: str,
        thread_id: str | None,
        reply_to: str | None,
    ) -> DraftRecord:
        safe_subject, _ = sanitize_text(subject)
        safe_text, _ = sanitize_text(text)
        draft_id = str(uuid.uuid4())
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO communication_drafts "
                "(draft_id, task_id, source, recipient_entity_id, conversation_id, subject, "
                "text, thread_id, reply_to, state, evidence_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', '{}', ?, ?)",
                (
                    draft_id,
                    task_id,
                    source.value,
                    recipient_entity_id,
                    conversation_id,
                    safe_subject,
                    safe_text,
                    thread_id,
                    reply_to,
                    now,
                    now,
                ),
            )
        return self.get_draft(draft_id)

    def get_draft(self, draft_id: str) -> DraftRecord:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM communication_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
        if row is None:
            raise KeyError(draft_id)
        return self._draft(row)

    def mark_sent(
        self, draft_id: str, *, external_message_id: str, evidence: dict[str, Any]
    ) -> DraftRecord:
        safe_evidence, _ = sanitize_payload(evidence)
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "UPDATE communication_drafts SET state = 'sent', external_message_id = ?, "
                "evidence_json = ?, updated_at = ? WHERE draft_id = ? AND state = 'draft'",
                (
                    external_message_id,
                    json.dumps(safe_evidence, ensure_ascii=False),
                    utc_now(),
                    draft_id,
                ),
            )
        if cursor.rowcount != 1:
            existing = self.get_draft(draft_id)
            if existing.state == "sent":
                return existing
            raise ValueError("Draft is not sendable")
        return self.get_draft(draft_id)

    def mark_submission_unknown(self, draft_id: str, *, evidence: dict[str, Any]) -> DraftRecord:
        safe_evidence, _ = sanitize_payload(evidence)
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "UPDATE communication_drafts SET state='submitted_unknown', "
                "evidence_json=?, updated_at=? WHERE draft_id=? AND state='draft'",
                (json.dumps(safe_evidence, ensure_ascii=False), utc_now(), draft_id),
            )
        if cursor.rowcount != 1:
            existing = self.get_draft(draft_id)
            if existing.state == "submitted_unknown":
                return existing
            raise ValueError("Draft is not sendable")
        return self.get_draft(draft_id)

    def configure_connector(
        self, provider: CommunicationSource, *, enabled: bool, scopes: list[str]
    ) -> None:
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO connectors(provider, enabled, scopes_json, status, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(provider) DO UPDATE SET "
                "enabled=excluded.enabled, scopes_json=excluded.scopes_json, "
                "status=excluded.status, updated_at=excluded.updated_at",
                (
                    provider.value,
                    int(enabled),
                    json.dumps(sorted(set(scopes))),
                    "active" if enabled else "revoked",
                    utc_now(),
                ),
            )

    def connector(self, provider: CommunicationSource) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM connectors WHERE provider = ?", (provider.value,)
            ).fetchone()
        if row is None:
            return {"provider": provider.value, "enabled": False, "scopes": [], "status": "missing"}
        result = dict(row)
        result["enabled"] = bool(result["enabled"])
        result["scopes"] = json.loads(result.pop("scopes_json"))
        return result

    def connectors(self) -> list[dict[str, Any]]:
        return [self.connector(provider) for provider in CommunicationSource]

    @staticmethod
    def _message(row: Any) -> CommunicationSearchHit:
        return CommunicationSearchHit(
            message_id=row["message_id"],
            source=row["source"],
            conversation_id=row["conversation_id"],
            thread_id=row["thread_id"],
            sender_entity_id=row["sender_entity_id"],
            timestamp=row["timestamp"],
            text=row["text"],
            source_reference=row["source_reference"],
        )

    @staticmethod
    def _draft(row: Any) -> DraftRecord:
        return DraftRecord(
            draft_id=row["draft_id"],
            task_id=row["task_id"],
            source=row["source"],
            recipient_entity_id=row["recipient_entity_id"],
            conversation_id=row["conversation_id"],
            subject=row["subject"],
            text=row["text"],
            thread_id=row["thread_id"],
            reply_to=row["reply_to"],
            state=row["state"],
            external_message_id=row["external_message_id"],
            evidence=json.loads(row["evidence_json"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
