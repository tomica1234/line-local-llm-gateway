from __future__ import annotations

import json
import math
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from ..storage import Storage, utc_now
from .embedding import EmbeddingProvider
from .models import (
    EntityCreate,
    EventCreate,
    EventRecord,
    MemoryCreate,
    MemoryKind,
    MemoryRecord,
    MemoryUpdate,
    PreferenceUpsert,
    PrivacyLevel,
    SearchHit,
)
from .sanitizer import sanitize_payload, sanitize_text

MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
    event_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    content TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    device_id TEXT,
    provenance_json TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    source_reference TEXT,
    retention_until TEXT,
    redacted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_raw_events_user_time
ON raw_events(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_raw_events_retention ON raw_events(retention_until);

CREATE VIRTUAL TABLE IF NOT EXISTS raw_event_fts USING fts5(
    event_id UNINDEXED,
    user_id UNINDEXED,
    content,
    source,
    event_type,
    tokenize='trigram'
);

CREATE TABLE IF NOT EXISTS memories (
    memory_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    statement TEXT NOT NULL,
    kind TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_event_ids_json TEXT NOT NULL,
    retention_until TEXT,
    metadata_json TEXT NOT NULL,
    embedding_state TEXT NOT NULL DEFAULT 'not_requested',
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memories_user_updated
ON memories(user_id, deleted_at, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_memories_retention ON memories(retention_until);

CREATE TABLE IF NOT EXISTS memory_evidence (
    memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES raw_events(event_id) ON DELETE RESTRICT,
    PRIMARY KEY(memory_id, event_id)
);

CREATE TABLE IF NOT EXISTS memory_embeddings (
    memory_id TEXT PRIMARY KEY REFERENCES memories(memory_id) ON DELETE CASCADE,
    model_id TEXT NOT NULL,
    vector_json TEXT NOT NULL,
    dimensions INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_relations (
    source_memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
    target_memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    evidence_event_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(source_memory_id, target_memory_id, relation_type)
);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    memory_id UNINDEXED,
    user_id UNINDEXED,
    statement,
    kind,
    tokenize='trigram'
);

CREATE TABLE IF NOT EXISTS preferences (
    preference_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_event_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, key)
);

CREATE TABLE IF NOT EXISTS preference_evidence (
    preference_id TEXT NOT NULL REFERENCES preferences(preference_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES raw_events(event_id) ON DELETE RESTRICT,
    PRIMARY KEY(preference_id, event_id)
);

CREATE TABLE IF NOT EXISTS entities (
    entity_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    aliases_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entities_user_type
ON entities(user_id, entity_type, canonical_name);

CREATE VIRTUAL TABLE IF NOT EXISTS entity_fts USING fts5(
    entity_id UNINDEXED,
    user_id UNINDEXED,
    canonical_name,
    aliases,
    entity_type,
    tokenize='trigram'
);

CREATE TABLE IF NOT EXISTS decision_logs (
    decision_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    task_id TEXT,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_event_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decision_evidence (
    decision_id TEXT NOT NULL REFERENCES decision_logs(decision_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES raw_events(event_id) ON DELETE RESTRICT,
    PRIMARY KEY(decision_id, event_id)
);
"""


def _retention_until(days: int | None, default_days: int | None = None) -> str | None:
    effective = days if days is not None else default_days
    if effective is None:
        return None
    return (datetime.now(UTC) + timedelta(days=effective)).isoformat(timespec="milliseconds")


def _fts_query(query: str) -> str:
    escaped = query.replace('"', '""')
    return f'"{escaped}"'


def _fts_trigram_or_query(text: str, *, max_terms: int = 64) -> str:
    compact = "".join(text.split())
    terms = list(dict.fromkeys(compact[index : index + 3] for index in range(len(compact) - 2)))
    return " OR ".join(_fts_query(term) for term in terms[:max_terms])


class MemoryStore:
    def __init__(
        self,
        storage: Storage,
        *,
        default_raw_retention_days: int = 90,
        embedding_provider: EmbeddingProvider | None = None,
    ):
        self.storage = storage
        self.default_raw_retention_days = default_raw_retention_days
        self.embedding_provider = embedding_provider

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(MEMORY_SCHEMA)

    def append_event(self, *, user_id: str, event: EventCreate) -> EventRecord | None:
        if event.privacy_level is PrivacyLevel.DROP:
            return None
        event_id = str(uuid.uuid4())
        event_timestamp = event.timestamp or datetime.now(UTC)
        if event_timestamp.tzinfo is None:
            event_timestamp = event_timestamp.replace(tzinfo=UTC)
        timestamp = event_timestamp.astimezone(UTC).isoformat(timespec="milliseconds")
        content, content_redacted = sanitize_text(event.content)
        payload, payload_redacted = sanitize_payload(event.payload)
        provenance, provenance_redacted = sanitize_payload(event.provenance)
        if event.privacy_level is PrivacyLevel.ORIGIN_ONLY:
            content = ""
            payload = {
                key: value
                for key, value in payload.items()
                if key in {"origin", "domain", "url_origin"}
            }
            content_redacted = True
        retention_until = _retention_until(event.retention_days, self.default_raw_retention_days)
        created_at = utc_now()
        redacted = content_redacted or payload_redacted or provenance_redacted
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO raw_events(event_id, user_id, event_type, source, content, "
                "payload_json, timestamp, device_id, provenance_json, trust_level, "
                "source_reference, retention_until, redacted, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    user_id,
                    event.event_type,
                    event.source,
                    content,
                    json.dumps(payload, ensure_ascii=False),
                    timestamp,
                    event.device_id,
                    json.dumps(provenance, ensure_ascii=False),
                    event.trust_level.value,
                    event.source_reference,
                    retention_until,
                    int(redacted),
                    created_at,
                ),
            )
            if content:
                connection.execute(
                    "INSERT INTO raw_event_fts(event_id, user_id, content, source, event_type) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (event_id, user_id, content, event.source, event.event_type),
                )
        return self.get_event(event_id)

    def get_event(self, event_id: str) -> EventRecord:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM raw_events WHERE event_id=?", (event_id,)
            ).fetchone()
        if row is None:
            raise KeyError(event_id)
        return self._event_from_row(row)

    def list_events(self, *, user_id: str, limit: int = 100) -> list[EventRecord]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM raw_events WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def remember(self, *, user_id: str, memory: MemoryCreate) -> MemoryRecord:
        statement, redacted = sanitize_text(memory.statement)
        if redacted and not statement.replace("[REDACTED]", "").strip():
            raise ValueError("A memory cannot consist only of sensitive data")
        self._validate_evidence(user_id, memory.evidence_event_ids)
        evidence_ids = list(dict.fromkeys(memory.evidence_event_ids))
        now = utc_now()
        clean_metadata, _ = sanitize_payload(memory.metadata)
        with self.storage.read_connection() as connection:
            existing = connection.execute(
                "SELECT memory_id, confidence, evidence_event_ids_json FROM memories "
                "WHERE user_id=? AND kind=? AND statement=? AND deleted_at IS NULL",
                (user_id, memory.kind.value, statement),
            ).fetchone()
        if existing:
            memory_id = existing["memory_id"]
            merged_evidence = list(
                dict.fromkeys([*json.loads(existing["evidence_event_ids_json"]), *evidence_ids])
            )
            with self.storage.transaction() as connection:
                connection.execute(
                    "UPDATE memories SET confidence=?, evidence_event_ids_json=?, "
                    "metadata_json=?, updated_at=? WHERE memory_id=?",
                    (
                        max(float(existing["confidence"]), memory.confidence),
                        json.dumps(merged_evidence),
                        json.dumps(clean_metadata, ensure_ascii=False),
                        now,
                        memory_id,
                    ),
                )
                connection.executemany(
                    "INSERT OR IGNORE INTO memory_evidence(memory_id, event_id) VALUES (?, ?)",
                    [(memory_id, event_id) for event_id in merged_evidence],
                )
            return self.get_memory(memory_id)

        memory_id = str(uuid.uuid4())
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO memories(memory_id, user_id, statement, kind, confidence, "
                "evidence_event_ids_json, retention_until, metadata_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    memory_id,
                    user_id,
                    statement,
                    memory.kind.value,
                    memory.confidence,
                    json.dumps(evidence_ids),
                    _retention_until(memory.retention_days),
                    json.dumps(clean_metadata, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO memory_fts(memory_id, user_id, statement, kind) VALUES (?, ?, ?, ?)",
                (memory_id, user_id, statement, memory.kind.value),
            )
            connection.executemany(
                "INSERT INTO memory_evidence(memory_id, event_id) VALUES (?, ?)",
                [(memory_id, event_id) for event_id in evidence_ids],
            )
            if memory.supersedes_memory_id:
                previous = connection.execute(
                    "SELECT user_id FROM memories WHERE memory_id=? AND deleted_at IS NULL",
                    (memory.supersedes_memory_id,),
                ).fetchone()
                if previous is None or previous["user_id"] != user_id:
                    raise ValueError("Superseded memory must exist and belong to the user")
                connection.execute(
                    "INSERT INTO memory_relations(source_memory_id, target_memory_id, "
                    "relation_type, evidence_event_ids_json, created_at) VALUES (?, ?, "
                    "'supersedes', ?, ?)",
                    (
                        memory_id,
                        memory.supersedes_memory_id,
                        json.dumps(evidence_ids),
                        now,
                    ),
                )
        self._embed_memory(memory_id, statement)
        return self.get_memory(memory_id)

    def get_memory(self, memory_id: str) -> MemoryRecord:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM memories WHERE memory_id=? AND deleted_at IS NULL", (memory_id,)
            ).fetchone()
        if row is None:
            raise KeyError(memory_id)
        return self._memory_from_row(row)

    def list_memories(
        self, *, user_id: str, kind: MemoryKind | None = None, limit: int = 100
    ) -> list[MemoryRecord]:
        sql = "SELECT * FROM memories WHERE user_id=? AND deleted_at IS NULL"
        params: list[Any] = [user_id]
        if kind:
            sql += " AND kind=?"
            params.append(kind.value)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        with self.storage.read_connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [self._memory_from_row(row) for row in rows]

    def update_memory(self, memory_id: str, update: MemoryUpdate) -> MemoryRecord:
        current = self.get_memory(memory_id)
        statement = update.statement if update.statement is not None else current.statement
        statement, redacted = sanitize_text(statement)
        if redacted and not statement.replace("[REDACTED]", "").strip():
            raise ValueError("A memory cannot consist only of sensitive data")
        confidence = update.confidence if update.confidence is not None else current.confidence
        metadata = update.metadata if update.metadata is not None else current.metadata
        clean_metadata, _ = sanitize_payload(metadata)
        retention_until = (
            _retention_until(update.retention_days)
            if update.retention_days is not None
            else current.retention_until
        )
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE memories SET statement=?, confidence=?, retention_until=?, "
                "metadata_json=?, updated_at=? WHERE memory_id=? AND deleted_at IS NULL",
                (
                    statement,
                    confidence,
                    retention_until,
                    json.dumps(clean_metadata, ensure_ascii=False),
                    now,
                    memory_id,
                ),
            )
            connection.execute("DELETE FROM memory_fts WHERE memory_id=?", (memory_id,))
            connection.execute(
                "INSERT INTO memory_fts(memory_id, user_id, statement, kind) VALUES (?, ?, ?, ?)",
                (memory_id, current.user_id, statement, current.kind.value),
            )
        return self.get_memory(memory_id)

    def forget(self, *, user_id: str, query: str) -> list[str]:
        hits = self.search_memories(user_id=user_id, query=query, limit=100)
        memory_ids = [hit.record_id for hit in hits]
        if not memory_ids:
            return []
        placeholders = ",".join("?" for _ in memory_ids)
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                f"UPDATE memories SET deleted_at=?, updated_at=? "
                f"WHERE user_id=? AND memory_id IN ({placeholders})",
                [now, now, user_id, *memory_ids],
            )
            connection.executemany(
                "DELETE FROM memory_fts WHERE memory_id=?",
                [(memory_id,) for memory_id in memory_ids],
            )
            connection.executemany(
                "DELETE FROM memory_evidence WHERE memory_id=?",
                [(memory_id,) for memory_id in memory_ids],
            )
        return memory_ids

    def delete_memory(self, *, user_id: str, memory_id: str) -> None:
        memory = self.get_memory(memory_id)
        if memory.user_id != user_id:
            raise KeyError(memory_id)
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE memories SET deleted_at=?, updated_at=? WHERE memory_id=?",
                (now, now, memory_id),
            )
            connection.execute("DELETE FROM memory_fts WHERE memory_id=?", (memory_id,))
            connection.execute("DELETE FROM memory_evidence WHERE memory_id=?", (memory_id,))

    def search_memories(self, *, user_id: str, query: str, limit: int = 50) -> list[SearchHit]:
        query = query.strip()
        if not query:
            return []
        with self.storage.read_connection() as connection:
            if len(query) >= 3:
                rows = connection.execute(
                    "SELECT f.memory_id, f.statement, f.kind, bm25(memory_fts) AS rank, "
                    "m.updated_at, m.confidence FROM memory_fts AS f "
                    "JOIN memories AS m ON m.memory_id=f.memory_id "
                    "WHERE memory_fts MATCH ? AND f.user_id=? AND m.deleted_at IS NULL "
                    "ORDER BY rank LIMIT ?",
                    (_fts_query(query), user_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT memory_id, statement, kind, 0.0 AS rank, updated_at, confidence "
                    "FROM memories WHERE user_id=? AND deleted_at IS NULL AND statement LIKE ? "
                    "ORDER BY updated_at DESC LIMIT ?",
                    (user_id, f"%{query}%", limit),
                ).fetchall()
        query_vector = self._try_embed(query)
        embedding_scores = self._embedding_scores(user_id, query_vector) if query_vector else {}
        lexical = {row["memory_id"]: float(-row["rank"]) for row in rows}
        candidate_ids = set(lexical) | set(embedding_scores)
        if not candidate_ids:
            return []
        placeholders = ",".join("?" for _ in candidate_ids)
        with self.storage.read_connection() as connection:
            records = connection.execute(
                "SELECT memory_id, statement, kind, updated_at, confidence, metadata_json "
                "FROM memories WHERE user_id=? AND deleted_at IS NULL "
                f"AND memory_id IN ({placeholders})",
                [user_id, *candidate_ids],
            ).fetchall()
        lexical_max = max((abs(value) for value in lexical.values()), default=1.0) or 1.0
        now = datetime.now(UTC)
        hits: list[SearchHit] = []
        for row in records:
            metadata = json.loads(row["metadata_json"])
            age_days = max(
                0.0,
                (now - datetime.fromisoformat(row["updated_at"]).astimezone(UTC)).total_seconds()
                / 86_400,
            )
            recency = math.exp(-age_days / 180)
            importance = {"high": 1.0, "medium": 0.6, "low": 0.2}.get(
                str(metadata.get("importance", "medium")).casefold(), 0.6
            )
            lexical_score = max(0.0, lexical.get(row["memory_id"], 0.0) / lexical_max)
            embedding_score = max(0.0, embedding_scores.get(row["memory_id"], 0.0))
            relation = self._entity_relation_score(query, metadata)
            if query_vector:
                score = (
                    lexical_score * 0.35
                    + embedding_score * 0.35
                    + recency * 0.1
                    + importance * 0.08
                    + float(row["confidence"]) * 0.07
                    + relation * 0.05
                )
            else:
                score = (
                    lexical_score * 0.7
                    + recency * 0.1
                    + importance * 0.08
                    + float(row["confidence"]) * 0.07
                    + relation * 0.05
                )
            hits.append(
                SearchHit(
                    record_type="memory",
                    record_id=row["memory_id"],
                    source=row["kind"],
                    text=row["statement"],
                    timestamp=row["updated_at"],
                    score=round(score, 6),
                    metadata={
                        "confidence": row["confidence"],
                        "lexical_score": round(lexical_score, 6),
                        "embedding_score": round(embedding_score, 6) if query_vector else None,
                        "recency_score": round(recency, 6),
                        "importance_score": importance,
                        "entity_relation_score": relation,
                    },
                )
            )
        return sorted(hits, key=lambda item: (item.score, item.timestamp), reverse=True)[:limit]

    def personal_search(self, *, user_id: str, query: str, limit: int = 50) -> list[SearchHit]:
        memory_hits = self.search_memories(user_id=user_id, query=query, limit=limit)
        query = query.strip()
        event_hits: list[SearchHit] = []
        if query:
            with self.storage.read_connection() as connection:
                if len(query) >= 3:
                    rows = connection.execute(
                        "SELECT f.event_id, f.content, f.source, f.event_type, "
                        "bm25(raw_event_fts) AS rank, e.timestamp, e.source_reference "
                        "FROM raw_event_fts AS f JOIN raw_events AS e ON e.event_id=f.event_id "
                        "WHERE raw_event_fts MATCH ? AND f.user_id=? ORDER BY rank LIMIT ?",
                        (_fts_query(query), user_id, limit),
                    ).fetchall()
                else:
                    rows = connection.execute(
                        "SELECT event_id, content, source, event_type, 0.0 AS rank, timestamp, "
                        "source_reference FROM raw_events WHERE user_id=? AND content LIKE ? "
                        "ORDER BY timestamp DESC LIMIT ?",
                        (user_id, f"%{query}%", limit),
                    ).fetchall()
            event_hits = [
                SearchHit(
                    record_type="event",
                    record_id=row["event_id"],
                    source=row["source"],
                    text=row["content"],
                    timestamp=row["timestamp"],
                    score=float(-row["rank"]),
                    metadata={
                        "event_type": row["event_type"],
                        "source_reference": row["source_reference"],
                    },
                )
                for row in rows
            ]
        return sorted(
            [*memory_hits, *event_hits],
            key=lambda hit: (hit.score, hit.timestamp),
            reverse=True,
        )[:limit]

    def relevant_memories(self, *, user_id: str, text: str, limit: int = 5) -> list[SearchHit]:
        if self.embedding_provider is not None:
            return self.search_memories(user_id=user_id, query=text, limit=limit)
        match_query = _fts_trigram_or_query(text)
        if not match_query:
            return []
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT f.memory_id, f.statement, f.kind, bm25(memory_fts) AS rank, "
                "m.updated_at, m.confidence FROM memory_fts AS f "
                "JOIN memories AS m ON m.memory_id=f.memory_id "
                "WHERE memory_fts MATCH ? AND f.user_id=? AND m.deleted_at IS NULL "
                "ORDER BY rank LIMIT ?",
                (match_query, user_id, limit),
            ).fetchall()
        return [
            SearchHit(
                record_type="memory",
                record_id=row["memory_id"],
                source=row["kind"],
                text=row["statement"],
                timestamp=row["updated_at"],
                score=float(-row["rank"]),
                metadata={"confidence": row["confidence"]},
            )
            for row in rows
        ]

    def upsert_preference(self, *, user_id: str, preference: PreferenceUpsert) -> dict[str, Any]:
        self._validate_evidence(user_id, preference.evidence_event_ids)
        clean_value, _ = sanitize_payload(preference.value)
        now = utc_now()
        preference_id = str(uuid.uuid4())
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO preferences(preference_id, user_id, key, value_json, confidence, "
                "evidence_event_ids_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(user_id, key) DO UPDATE SET value_json=excluded.value_json, "
                "confidence=excluded.confidence, "
                "evidence_event_ids_json=excluded.evidence_event_ids_json, "
                "updated_at=excluded.updated_at",
                (
                    preference_id,
                    user_id,
                    preference.key,
                    json.dumps(clean_value, ensure_ascii=False),
                    preference.confidence,
                    json.dumps(preference.evidence_event_ids),
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM preferences WHERE user_id=? AND key=?",
                (user_id, preference.key),
            ).fetchone()
            connection.execute(
                "DELETE FROM preference_evidence WHERE preference_id=?",
                (row["preference_id"],),
            )
            connection.executemany(
                "INSERT INTO preference_evidence(preference_id, event_id) VALUES (?, ?)",
                [
                    (row["preference_id"], event_id)
                    for event_id in dict.fromkeys(preference.evidence_event_ids)
                ],
            )
        return self._json_row(row, ("value_json", "evidence_event_ids_json"))

    def list_preferences(self, *, user_id: str) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM preferences WHERE user_id=? ORDER BY key", (user_id,)
            ).fetchall()
        return [self._json_row(row, ("value_json", "evidence_event_ids_json")) for row in rows]

    def create_entity(self, *, user_id: str, entity: EntityCreate) -> dict[str, Any]:
        entity_id = str(uuid.uuid4())
        aliases = list(dict.fromkeys(alias.strip() for alias in entity.aliases if alias.strip()))
        clean_metadata, _ = sanitize_payload(entity.metadata)
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO entities(entity_id, user_id, entity_type, canonical_name, "
                "aliases_json, metadata_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entity_id,
                    user_id,
                    entity.entity_type,
                    entity.canonical_name,
                    json.dumps(aliases, ensure_ascii=False),
                    json.dumps(clean_metadata, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO entity_fts(entity_id, user_id, canonical_name, aliases, entity_type) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    entity_id,
                    user_id,
                    entity.canonical_name,
                    " ".join(aliases),
                    entity.entity_type,
                ),
            )
        return self.get_entity(entity_id)

    def get_entity(self, entity_id: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM entities WHERE entity_id=?", (entity_id,)
            ).fetchone()
        if row is None:
            raise KeyError(entity_id)
        return self._json_row(row, ("aliases_json", "metadata_json"))

    def record_decision(
        self,
        *,
        user_id: str,
        task_id: str | None,
        decision: str,
        reason: str,
        evidence_event_ids: list[str],
    ) -> str:
        self._validate_evidence(user_id, evidence_event_ids)
        decision_id = str(uuid.uuid4())
        clean_decision, _ = sanitize_text(decision)
        clean_reason, _ = sanitize_text(reason)
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO decision_logs(decision_id, user_id, task_id, decision, reason, "
                "evidence_event_ids_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    decision_id,
                    user_id,
                    task_id,
                    clean_decision,
                    clean_reason,
                    json.dumps(evidence_event_ids),
                    utc_now(),
                ),
            )
            connection.executemany(
                "INSERT INTO decision_evidence(decision_id, event_id) VALUES (?, ?)",
                [(decision_id, event_id) for event_id in dict.fromkeys(evidence_event_ids)],
            )
        return decision_id

    def summarize_period(
        self,
        *,
        user_id: str,
        summary_key: str,
        start_at: datetime,
        end_at: datetime,
    ) -> MemoryRecord | None:
        if start_at.tzinfo is None or end_at.tzinfo is None or start_at >= end_at:
            raise ValueError("Summary interval must be timezone-aware and increasing")
        with self.storage.read_connection() as connection:
            existing = connection.execute(
                "SELECT memory_id FROM memories WHERE user_id=? AND kind='summary' "
                "AND deleted_at IS NULL "
                "AND json_extract(metadata_json, '$.summary_key')=?",
                (user_id, summary_key),
            ).fetchone()
            rows = connection.execute(
                "SELECT event_id, source, event_type, content FROM raw_events "
                "WHERE user_id=? AND timestamp>=? AND timestamp<? "
                "ORDER BY timestamp LIMIT 5000",
                (
                    user_id,
                    start_at.astimezone(UTC).isoformat(timespec="milliseconds"),
                    end_at.astimezone(UTC).isoformat(timespec="milliseconds"),
                ),
            ).fetchall()
        if existing:
            return self.get_memory(existing["memory_id"])
        if not rows:
            return None
        counts: dict[str, int] = {}
        highlights: list[str] = []
        for row in rows:
            key = f"{row['source']}:{row['event_type']}"
            counts[key] = counts.get(key, 0) + 1
            content = " ".join(str(row["content"]).split())
            if content and len(highlights) < 20:
                highlights.append(content[:200])
        count_text = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
        highlight_text = " / ".join(highlights)
        statement = f"{summary_key}: {len(rows)} events ({count_text})"
        if highlight_text:
            statement += f". Highlights: {highlight_text}"
        return self.remember(
            user_id=user_id,
            memory=MemoryCreate(
                statement=statement[:20_000],
                kind=MemoryKind.SUMMARY,
                confidence=0.8,
                evidence_event_ids=[row["event_id"] for row in rows[:100]],
                metadata={
                    "summary_key": summary_key,
                    "event_count": len(rows),
                    "source_event_counts": counts,
                    "generated_by": "deterministic_compactor",
                },
            ),
        )

    def decay_memories(
        self,
        *,
        user_id: str,
        before: datetime,
        factor: float = 0.95,
        floor: float = 0.3,
    ) -> int:
        if before.tzinfo is None:
            raise ValueError("Memory decay cutoff must be timezone-aware")
        if not 0 < factor < 1 or not 0 <= floor <= 1:
            raise ValueError("Invalid memory decay parameters")
        cutoff = before.astimezone(UTC).isoformat(timespec="milliseconds")
        now = utc_now()
        changed = 0
        with self.storage.transaction() as connection:
            rows = connection.execute(
                "SELECT memory_id, confidence, metadata_json FROM memories "
                "WHERE user_id=? AND deleted_at IS NULL AND updated_at<? "
                "AND kind NOT IN ('preference', 'commitment')",
                (user_id, cutoff),
            ).fetchall()
            for row in rows:
                metadata = json.loads(row["metadata_json"])
                if metadata.get("pinned") or metadata.get("importance") == "high":
                    continue
                confidence = float(row["confidence"])
                next_confidence = max(floor, confidence * factor)
                if next_confidence >= confidence:
                    continue
                connection.execute(
                    "UPDATE memories SET confidence=?, updated_at=? WHERE memory_id=?",
                    (next_confidence, now, row["memory_id"]),
                )
                changed += 1
        return changed

    def purge_expired(self, *, now: datetime | None = None) -> dict[str, int]:
        reference = (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="milliseconds")
        with self.storage.transaction() as connection:
            event_rows = connection.execute(
                "SELECT event_id FROM raw_events WHERE retention_until IS NOT NULL "
                "AND retention_until <= ?",
                (reference,),
            ).fetchall()
            memory_rows = connection.execute(
                "SELECT memory_id FROM memories WHERE deleted_at IS NULL "
                "AND retention_until IS NOT NULL AND retention_until <= ?",
                (reference,),
            ).fetchall()
            expired_event_ids = [row["event_id"] for row in event_rows]
            referenced: set[str] = set()
            if expired_event_ids:
                placeholders = ",".join("?" for _ in expired_event_ids)
                reference_rows = connection.execute(
                    "SELECT event_id FROM memory_evidence "
                    f"WHERE event_id IN ({placeholders}) UNION "
                    "SELECT event_id FROM preference_evidence "
                    f"WHERE event_id IN ({placeholders}) UNION "
                    "SELECT event_id FROM decision_evidence "
                    f"WHERE event_id IN ({placeholders})",
                    [*expired_event_ids, *expired_event_ids, *expired_event_ids],
                ).fetchall()
                referenced = {row["event_id"] for row in reference_rows}
            connection.executemany(
                "DELETE FROM raw_event_fts WHERE event_id=?",
                [(event_id,) for event_id in expired_event_ids],
            )
            connection.executemany(
                "UPDATE raw_events SET content='', payload_json='{}', redacted=1, "
                "retention_until=NULL WHERE event_id=?",
                [(event_id,) for event_id in referenced],
            )
            deletable = [event_id for event_id in expired_event_ids if event_id not in referenced]
            connection.executemany(
                "DELETE FROM raw_events WHERE event_id=?",
                [(event_id,) for event_id in deletable],
            )
            connection.executemany(
                "DELETE FROM memory_fts WHERE memory_id=?",
                [(row["memory_id"],) for row in memory_rows],
            )
            connection.execute(
                "UPDATE memories SET deleted_at=?, updated_at=? WHERE deleted_at IS NULL "
                "AND retention_until IS NOT NULL AND retention_until <= ?",
                (reference, reference, reference),
            )
            connection.executemany(
                "DELETE FROM memory_evidence WHERE memory_id=?",
                [(row["memory_id"],) for row in memory_rows],
            )
        return {
            "events": len(event_rows),
            "event_tombstones": len(referenced),
            "memories": len(memory_rows),
        }

    def _validate_evidence(self, user_id: str, event_ids: list[str]) -> None:
        if not event_ids:
            return
        unique_ids = list(dict.fromkeys(event_ids))
        placeholders = ",".join("?" for _ in unique_ids)
        with self.storage.read_connection() as connection:
            count = connection.execute(
                f"SELECT COUNT(*) AS count FROM raw_events "
                f"WHERE user_id=? AND event_id IN ({placeholders})",
                [user_id, *unique_ids],
            ).fetchone()["count"]
        if count != len(unique_ids):
            raise ValueError("Memory evidence must reference existing events owned by the user")

    def relations(self, memory_id: str) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM memory_relations WHERE source_memory_id=? OR target_memory_id=? "
                "ORDER BY created_at",
                (memory_id, memory_id),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["evidence_event_ids"] = json.loads(item.pop("evidence_event_ids_json"))
            result.append(item)
        return result

    def _embed_memory(self, memory_id: str, statement: str) -> None:
        if self.embedding_provider is None:
            return
        vector = self._try_embed(statement)
        state = "ready" if vector else "failed"
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE memories SET embedding_state=? WHERE memory_id=?", (state, memory_id)
            )
            if vector:
                connection.execute(
                    "INSERT OR REPLACE INTO memory_embeddings(memory_id, model_id, vector_json, "
                    "dimensions, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        memory_id,
                        self.embedding_provider.model_id,
                        json.dumps(vector),
                        len(vector),
                        utc_now(),
                    ),
                )

    def _try_embed(self, text: str) -> list[float] | None:
        if self.embedding_provider is None:
            return None
        try:
            return self.embedding_provider.embed(text)
        except Exception:
            return None

    def _embedding_scores(self, user_id: str, query_vector: list[float]) -> dict[str, float]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT e.memory_id, e.vector_json FROM memory_embeddings e "
                "JOIN memories m ON m.memory_id=e.memory_id "
                "WHERE m.user_id=? AND m.deleted_at IS NULL AND e.model_id=? LIMIT 2000",
                (user_id, self.embedding_provider.model_id if self.embedding_provider else ""),
            ).fetchall()
        result = {}
        query_norm = math.sqrt(sum(value * value for value in query_vector))
        if not query_norm:
            return result
        for row in rows:
            vector = json.loads(row["vector_json"])
            if len(vector) != len(query_vector):
                continue
            norm = math.sqrt(sum(float(value) * float(value) for value in vector))
            if norm:
                result[row["memory_id"]] = sum(
                    left * float(right) for left, right in zip(query_vector, vector, strict=True)
                ) / (query_norm * norm)
        return result

    @staticmethod
    def _entity_relation_score(query: str, metadata: dict[str, Any]) -> float:
        values = metadata.get("entities") or metadata.get("entity_ids") or []
        if isinstance(values, str):
            values = [values]
        lowered = query.casefold()
        return 1.0 if any(str(value).casefold() in lowered for value in values) else 0.0

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> EventRecord:
        return EventRecord(
            event_id=row["event_id"],
            user_id=row["user_id"],
            event_type=row["event_type"],
            source=row["source"],
            content=row["content"],
            payload=json.loads(row["payload_json"]),
            timestamp=row["timestamp"],
            device_id=row["device_id"],
            provenance=json.loads(row["provenance_json"]),
            trust_level=row["trust_level"],
            source_reference=row["source_reference"],
            retention_until=row["retention_until"],
            redacted=bool(row["redacted"]),
            created_at=row["created_at"],
        )

    @staticmethod
    def _memory_from_row(row: sqlite3.Row) -> MemoryRecord:
        return MemoryRecord(
            memory_id=row["memory_id"],
            user_id=row["user_id"],
            statement=row["statement"],
            kind=row["kind"],
            confidence=row["confidence"],
            evidence_event_ids=json.loads(row["evidence_event_ids_json"]),
            retention_until=row["retention_until"],
            metadata=json.loads(row["metadata_json"]),
            embedding_state=row["embedding_state"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _json_row(row: sqlite3.Row, fields: tuple[str, ...]) -> dict[str, Any]:
        result = dict(row)
        for field in fields:
            result[field.removesuffix("_json")] = json.loads(result.pop(field))
        return result
