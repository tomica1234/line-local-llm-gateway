from __future__ import annotations

import json
import uuid
from typing import Any

from ..migrations import Migration, apply_migrations
from ..storage import Storage, utc_now
from .models import (
    ContactCreate,
    ContactIdentity,
    ContactRecord,
    ResolutionCandidate,
    ResolutionResult,
)

CONTACTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (
    contact_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    entity_id TEXT,
    source TEXT NOT NULL,
    external_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, source, external_id)
);
CREATE TABLE IF NOT EXISTS contact_identities (
    contact_id TEXT NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    PRIMARY KEY(contact_id, kind, normalized_value)
);
CREATE INDEX IF NOT EXISTS idx_contact_identity_lookup
ON contact_identities(kind, normalized_value);
CREATE INDEX IF NOT EXISTS idx_contacts_name
ON contacts(user_id, display_name);
"""


def _contacts_v1(_connection: Any) -> None:
    return None


CONTACTS_MIGRATIONS = (Migration(1, "contacts-and-identities", _contacts_v1),)


class ContactsStore:
    def __init__(self, storage: Storage, *, user_id: str) -> None:
        self.storage = storage
        self.user_id = user_id

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(CONTACTS_SCHEMA)
            apply_migrations(connection, component="contacts", migrations=CONTACTS_MIGRATIONS)

    def upsert(self, value: ContactCreate) -> ContactRecord:
        now = utc_now()
        with self.storage.transaction() as connection:
            existing = None
            if value.external_id:
                existing = connection.execute(
                    "SELECT contact_id FROM contacts WHERE user_id=? AND source=? "
                    "AND external_id=?",
                    (self.user_id, value.source.value, value.external_id),
                ).fetchone()
            contact_id = str(existing["contact_id"]) if existing else str(uuid.uuid4())
            connection.execute(
                "INSERT INTO contacts(contact_id, user_id, display_name, aliases_json, entity_id, "
                "source, external_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(contact_id) DO UPDATE SET display_name=excluded.display_name, "
                "aliases_json=excluded.aliases_json, "
                "entity_id=COALESCE(excluded.entity_id, contacts.entity_id), "
                "external_id=excluded.external_id, updated_at=excluded.updated_at",
                (
                    contact_id,
                    self.user_id,
                    value.display_name.strip(),
                    json.dumps(self._aliases(value.aliases), ensure_ascii=False),
                    value.entity_id,
                    value.source.value,
                    value.external_id,
                    now,
                    now,
                ),
            )
            connection.execute("DELETE FROM contact_identities WHERE contact_id=?", (contact_id,))
            for identity in value.identities:
                normalized = self._normalize_identity(identity.kind.value, identity.value)
                connection.execute(
                    "INSERT INTO contact_identities(contact_id, kind, value, normalized_value, "
                    "label, verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        contact_id,
                        identity.kind.value,
                        identity.value.strip(),
                        normalized,
                        identity.label,
                        int(identity.verified),
                        now,
                    ),
                )
        return self.get(contact_id)

    def get(self, contact_id: str) -> ContactRecord:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM contacts WHERE contact_id=? AND user_id=?",
                (contact_id, self.user_id),
            ).fetchone()
            identities = connection.execute(
                "SELECT kind, value, label, verified FROM contact_identities "
                "WHERE contact_id=? ORDER BY kind, value",
                (contact_id,),
            ).fetchall()
        if row is None:
            raise KeyError(contact_id)
        value = dict(row)
        value["aliases"] = json.loads(value.pop("aliases_json"))
        value["identities"] = [
            ContactIdentity.model_validate(
                {**dict(identity), "verified": bool(identity["verified"])}
            )
            for identity in identities
        ]
        return ContactRecord.model_validate(value)

    def search(self, query: str, *, limit: int = 20) -> list[ContactRecord]:
        normalized = query.strip().casefold()
        if not normalized:
            return []
        pattern = f"%{normalized}%"
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT c.contact_id FROM contacts c LEFT JOIN contact_identities i "
                "ON i.contact_id=c.contact_id WHERE c.user_id=? AND "
                "(lower(c.display_name) LIKE ? OR lower(c.aliases_json) LIKE ? "
                "OR i.normalized_value LIKE ?) ORDER BY c.display_name LIMIT ?",
                (self.user_id, pattern, pattern, pattern, limit),
            ).fetchall()
        return [self.get(str(row["contact_id"])) for row in rows]

    def list(self, *, limit: int = 100) -> list[ContactRecord]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT contact_id FROM contacts WHERE user_id=? ORDER BY display_name LIMIT ?",
                (self.user_id, limit),
            ).fetchall()
        return [self.get(str(row["contact_id"])) for row in rows]

    def resolve(self, query: str, *, destination_kind: str | None = None) -> ResolutionResult:
        normalized = query.strip().casefold()
        records = self.search(query, limit=20)
        candidates: list[ResolutionCandidate] = []
        for record in records:
            aliases = [alias.casefold() for alias in record.aliases]
            destinations = [
                item
                for item in record.identities
                if destination_kind is None or item.kind.value == destination_kind
            ]
            identity_exact = any(
                self._normalize_identity(item.kind.value, item.value) == normalized
                for item in destinations
            )
            if record.display_name.casefold() == normalized:
                confidence, matched_by = 0.98, "display_name"
            elif identity_exact:
                confidence, matched_by = 1.0, "identity"
            elif normalized in aliases:
                confidence, matched_by = 0.94, "alias"
            else:
                confidence, matched_by = 0.70, "partial"
            if not destinations:
                confidence = min(confidence, 0.60)
            candidates.append(
                ResolutionCandidate(
                    contact_id=record.contact_id,
                    display_name=record.display_name,
                    entity_id=record.entity_id,
                    confidence=confidence,
                    matched_by=matched_by,
                    destinations=destinations,
                )
            )
        candidates.sort(key=lambda item: (-item.confidence, item.display_name))
        selected = candidates[0] if candidates else None
        unique = bool(
            selected
            and selected.confidence >= 0.90
            and selected.destinations
            and (len(candidates) == 1 or selected.confidence - candidates[1].confidence >= 0.10)
        )
        return ResolutionResult(
            query=query,
            status="resolved" if unique else "not_found" if not candidates else "ambiguous",
            selected=selected if unique else None,
            candidates=candidates[:10],
            requires_user_confirmation=not unique,
        )

    def link_identity(self, contact_id: str, *, entity_id: str) -> ContactRecord:
        with self.storage.transaction() as connection:
            entity = connection.execute(
                "SELECT entity_id FROM entities WHERE entity_id=? AND user_id=?",
                (entity_id, self.user_id),
            ).fetchone()
            if entity is None:
                raise ValueError("Contact must link to an existing owned memory entity")
            cursor = connection.execute(
                "UPDATE contacts SET entity_id=?, updated_at=? WHERE contact_id=? AND user_id=?",
                (entity_id, utc_now(), contact_id, self.user_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(contact_id)
        return self.get(contact_id)

    @staticmethod
    def _aliases(values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))

    @staticmethod
    def _normalize_identity(kind: str, value: str) -> str:
        normalized = value.strip().casefold()
        if kind == "phone":
            return "".join(
                character for character in normalized if character.isdigit() or character == "+"
            )
        return normalized
