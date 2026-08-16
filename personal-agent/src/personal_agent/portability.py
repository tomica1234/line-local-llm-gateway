from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

from .audit import redact
from .storage import Storage

DeleteScope = Literal[
    "activity",
    "memory",
    "communication",
    "calendar",
    "tasks",
    "economic",
    "audit",
    "all",
]

_EXPORT_TABLES = (
    "tasks",
    "task_events",
    "messages",
    "actions",
    "scheduled_jobs",
    "notifications",
    "notification_deliveries",
    "audit_events",
    "approvals",
    "raw_events",
    "memories",
    "preferences",
    "entities",
    "decision_logs",
    "communication_messages",
    "communication_drafts",
    "connectors",
    "calendar_events",
    "economic_intents",
    "budgets",
    "payees",
    "transactions",
    "sandbox_accounts",
    "opportunities",
    "preference_candidates",
    "workflow_candidates",
    "benchmark_runs",
)


class DataPortabilityService:
    def __init__(self, storage: Storage, *, user_id: str):
        self.storage = storage
        self.user_id = user_id

    def export(self) -> dict[str, Any]:
        data: dict[str, list[dict[str, Any]]] = {}
        with self.storage.read_connection() as connection:
            known = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            for table in _EXPORT_TABLES:
                if table not in known:
                    continue
                rows = connection.execute(f'SELECT * FROM "{table}"').fetchall()
                data[table] = [redact(dict(row)) for row in rows]
        return {
            "format": "personal-agent-export-v1",
            "exported_at": datetime.now(UTC).isoformat(),
            "user_id": self.user_id,
            "secret_values_included": False,
            "data": data,
        }

    def delete(self, scope: DeleteScope, *, confirmation: str) -> dict[str, Any]:
        expected = f"DELETE:{scope}"
        if confirmation != expected:
            raise ValueError(f"Confirmation must exactly equal {expected}")
        deleted: dict[str, int] = {}
        with self.storage.transaction() as connection:
            if scope == "activity":
                self._delete_event_subset(
                    connection,
                    "source IN ('safari_private', 'activity')",
                    deleted,
                )
            if scope in {"memory", "all"}:
                self._delete_tables(
                    connection,
                    (
                        "decision_evidence",
                        "decision_logs",
                        "preference_evidence",
                        "preferences",
                        "memory_evidence",
                        "memory_fts",
                        "memories",
                        "entity_fts",
                        "entities",
                        "preference_candidates",
                        "workflow_candidates",
                    ),
                    deleted,
                )
            if scope == "all":
                self._delete_event_subset(connection, "1=1", deleted)
            if scope in {"communication", "all"}:
                self._delete_tables(
                    connection,
                    (
                        "communication_fts",
                        "communication_messages",
                        "communication_drafts",
                        "connectors",
                    ),
                    deleted,
                )
            if scope in {"calendar", "all"}:
                self._delete_tables(connection, ("calendar_fts", "calendar_events"), deleted)
            if scope in {"economic", "all"}:
                self._delete_tables(
                    connection,
                    (
                        "transactions",
                        "economic_intents",
                        "budgets",
                        "payees",
                        "sandbox_accounts",
                    ),
                    deleted,
                )
            if scope in {"tasks", "all"}:
                self._delete_tables(
                    connection,
                    (
                        "opportunities",
                        "notification_deliveries",
                        "notifications",
                        "scheduled_jobs",
                        "approvals",
                        "actions",
                        "messages",
                        "channel_sessions",
                        "task_events",
                        "tasks",
                        "inbound_events",
                        "benchmark_runs",
                    ),
                    deleted,
                )
            if scope == "all":
                self._delete_tables(
                    connection,
                    (
                        "webauthn_sessions",
                        "webauthn_challenges",
                        "webauthn_credentials",
                    ),
                    deleted,
                )
            if scope in {"audit", "all"}:
                self._delete_tables(connection, ("audit_events",), deleted)
        return {"scope": scope, "deleted": deleted, "secret_store_untouched": True}

    @staticmethod
    def _delete_event_subset(
        connection: Any,
        predicate: str,
        deleted: dict[str, int],
    ) -> None:
        event_ids = [
            row["event_id"]
            for row in connection.execute(
                f"SELECT event_id FROM raw_events WHERE {predicate}"
            ).fetchall()
        ]
        if not event_ids:
            deleted["raw_events"] = 0
            return
        placeholders = ",".join("?" for _ in event_ids)
        references = 0
        for table in ("memory_evidence", "preference_evidence", "decision_evidence"):
            references += connection.execute(
                f'SELECT COUNT(*) FROM "{table}" WHERE event_id IN ({placeholders})',
                event_ids,
            ).fetchone()[0]
        if references:
            raise ValueError("Delete dependent memories before deleting referenced events")
        cursor = connection.execute(
            f"DELETE FROM raw_event_fts WHERE event_id IN ({placeholders})", event_ids
        )
        deleted["raw_event_fts"] = cursor.rowcount
        cursor = connection.execute(
            f"DELETE FROM raw_events WHERE event_id IN ({placeholders})", event_ids
        )
        deleted["raw_events"] = cursor.rowcount

    @staticmethod
    def _delete_tables(
        connection: Any,
        tables: tuple[str, ...],
        deleted: dict[str, int],
    ) -> None:
        known = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for table in tables:
            if table not in known:
                continue
            cursor = connection.execute(f'DELETE FROM "{table}"')
            deleted[table] = cursor.rowcount


def export_json_bytes(service: DataPortabilityService) -> bytes:
    return json.dumps(service.export(), ensure_ascii=False, indent=2, default=str).encode("utf-8")
