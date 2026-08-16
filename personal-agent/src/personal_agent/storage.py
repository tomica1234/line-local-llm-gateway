from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .types import Channel, RiskLevel, Route, TaskEventRecord, TaskRecord, TaskState


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    goal TEXT NOT NULL,
    state TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    route TEXT,
    source TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    plan_json TEXT NOT NULL DEFAULT '[]',
    result_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_state_updated ON tasks(state, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_user_updated ON tasks(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS task_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    state TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_events_task ON task_events(task_id, event_id);

CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    source TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_task ON messages(task_id, created_at);

CREATE TABLE IF NOT EXISTS channel_sessions (
    user_id TEXT NOT NULL,
    source TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    active_task_id TEXT REFERENCES tasks(task_id) ON DELETE SET NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(user_id, source, conversation_id)
);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    dry_run INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    reason TEXT NOT NULL,
    input_json TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_task ON actions(task_id, created_at);

CREATE TABLE IF NOT EXISTS scheduled_jobs (
    job_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    run_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_due ON scheduled_jobs(status, run_at);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE REFERENCES scheduled_jobs(job_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    text TEXT NOT NULL,
    status TEXT NOT NULL,
    lease_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_delivery
ON notifications(status, source, conversation_id, created_at);

CREATE TABLE IF NOT EXISTS notification_deliveries (
    delivery_id TEXT PRIMARY KEY,
    notification_id TEXT NOT NULL REFERENCES notifications(notification_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    lease_expires_at TEXT,
    external_id TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(notification_id, provider, target)
);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_claim
ON notification_deliveries(provider, target, status, next_attempt_at, created_at);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS inbound_events (
    source TEXT NOT NULL,
    external_event_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(source, external_event_id)
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    arguments_hash TEXT NOT NULL,
    input_summary_json TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    reason TEXT NOT NULL,
    state TEXT NOT NULL,
    decision_actor TEXT,
    decision_method TEXT,
    decided_at TEXT,
    consumed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(task_id, tool_name, arguments_hash)
);
CREATE INDEX IF NOT EXISTS idx_approvals_state_created ON approvals(state, created_at DESC);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    label TEXT NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    transports_json TEXT NOT NULL DEFAULT '[]',
    device_type TEXT NOT NULL,
    backed_up INTEGER NOT NULL,
    aaguid TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user
ON webauthn_credentials(user_id, revoked_at, created_at);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge_id TEXT PRIMARY KEY,
    challenge BLOB NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    user_id TEXT NOT NULL,
    approval_id TEXT REFERENCES approvals(approval_id) ON DELETE CASCADE,
    binding_hash TEXT NOT NULL,
    label TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expiry
ON webauthn_challenges(consumed_at, expires_at);

CREATE TABLE IF NOT EXISTS webauthn_sessions (
    session_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL REFERENCES webauthn_credentials(credential_id),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expiry
ON webauthn_sessions(revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
"""


TRANSIENT_STATES = (
    TaskState.RECEIVED,
    TaskState.UNDERSTANDING,
    TaskState.PLANNING,
    TaskState.EXECUTING,
    TaskState.VERIFYING,
    TaskState.RETRYING,
)


class Storage:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._notification_delivery_targets: set[tuple[str, str]] = set()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Public write transaction for bounded domain repositories."""
        with self._lock, self._connection() as connection:
            yield connection

    @contextmanager
    def read_connection(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            yield connection

    def initialize(self) -> None:
        with self._lock, self._connection() as connection:
            connection.executescript(SCHEMA)
            notification_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(notifications)").fetchall()
            }
            if "lease_expires_at" not in notification_columns:
                connection.execute("ALTER TABLE notifications ADD COLUMN lease_expires_at TEXT")
            now = utc_now()
            for key, value in {
                "global_pause": False,
                "finance_lock": True,
                "browser_lock": False,
                "secret_lock": True,
                "policy_version": 1,
                "activity_capture_enabled": False,
                "activity_blocked_domains": [],
            }.items():
                connection.execute(
                    "INSERT OR IGNORE INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value), now),
                )
        if os.name != "nt":
            self.path.chmod(0o600)

    def recover_incomplete_tasks(self) -> int:
        placeholders = ",".join("?" for _ in TRANSIENT_STATES)
        now = utc_now()
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                f"SELECT task_id, state FROM tasks WHERE state IN ({placeholders})",
                tuple(state.value for state in TRANSIENT_STATES),
            ).fetchall()
            for row in rows:
                connection.execute(
                    "UPDATE tasks SET state = ?, updated_at = ? WHERE task_id = ?",
                    (TaskState.PAUSED.value, now, row["task_id"]),
                )
                connection.execute(
                    "INSERT INTO task_events(task_id, event_type, state, payload_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        row["task_id"],
                        "recovered_after_restart",
                        TaskState.PAUSED.value,
                        json.dumps({"previous_state": row["state"]}),
                        now,
                    ),
                )
            return len(rows)

    def create_task(
        self,
        *,
        user_id: str,
        goal: str,
        source: Channel,
        conversation_id: str,
        risk_level: RiskLevel = RiskLevel.R0,
    ) -> TaskRecord:
        task_id = str(uuid.uuid4())
        now = utc_now()
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO tasks(task_id, user_id, goal, state, risk_level, source, "
                "conversation_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    task_id,
                    user_id,
                    goal,
                    TaskState.RECEIVED.value,
                    risk_level.value,
                    source.value,
                    conversation_id,
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO task_events(task_id, event_type, state, payload_json, created_at) "
                "VALUES (?, 'task_created', ?, '{}', ?)",
                (task_id, TaskState.RECEIVED.value, now),
            )
        return self.get_task(task_id)

    def get_task(self, task_id: str) -> TaskRecord:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(task_id)
        return self._task_from_row(row)

    def list_tasks(self, *, limit: int = 100) -> list[TaskRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM tasks ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._task_from_row(row) for row in rows]

    def update_task(
        self,
        task_id: str,
        *,
        state: TaskState | None = None,
        route: Route | None = None,
        risk_level: RiskLevel | None = None,
        plan: list[str] | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        event_type: str = "task_updated",
        event_payload: dict[str, Any] | None = None,
    ) -> TaskRecord:
        current = self.get_task(task_id)
        values = {
            "state": (state or current.state).value,
            "route": (route or current.route).value if (route or current.route) else None,
            "risk_level": (risk_level or current.risk_level).value,
            "plan_json": json.dumps(plan if plan is not None else current.plan),
            "result_json": json.dumps(result)
            if result is not None
            else (json.dumps(current.result) if current.result is not None else None),
            "error": error,
            "updated_at": utc_now(),
        }
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE tasks SET state=:state, route=:route, risk_level=:risk_level, "
                "plan_json=:plan_json, result_json=:result_json, error=:error, "
                "updated_at=:updated_at WHERE task_id=:task_id",
                {**values, "task_id": task_id},
            )
            connection.execute(
                "INSERT INTO task_events(task_id, event_type, state, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    task_id,
                    event_type,
                    values["state"],
                    json.dumps(event_payload or {}),
                    values["updated_at"],
                ),
            )
        return self.get_task(task_id)

    def list_task_events(self, task_id: str) -> list[TaskEventRecord]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM task_events WHERE task_id = ? ORDER BY event_id",
                (task_id,),
            ).fetchall()
        return [
            TaskEventRecord(
                event_id=row["event_id"],
                task_id=row["task_id"],
                event_type=row["event_type"],
                state=TaskState(row["state"]) if row["state"] else None,
                payload=json.loads(row["payload_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def record_message(
        self,
        *,
        task_id: str,
        user_id: str,
        source: Channel,
        conversation_id: str,
        direction: str,
        text: str,
    ) -> str:
        message_id = str(uuid.uuid4())
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO messages(message_id, task_id, user_id, source, conversation_id, "
                "direction, text, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    message_id,
                    task_id,
                    user_id,
                    source.value,
                    conversation_id,
                    direction,
                    text,
                    utc_now(),
                ),
            )
        return message_id

    def get_task_messages(self, task_id: str) -> list[dict[str, str]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT direction, text, source, created_at FROM messages "
                "WHERE task_id = ? ORDER BY created_at",
                (task_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def bind_channel_session(
        self, *, user_id: str, source: Channel, conversation_id: str, task_id: str
    ) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO channel_sessions(user_id, source, conversation_id, "
                "active_task_id, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, source, conversation_id) DO UPDATE "
                "SET active_task_id=excluded.active_task_id, updated_at=excluded.updated_at",
                (user_id, source.value, conversation_id, task_id, utc_now()),
            )

    def active_task_id(self, *, user_id: str, source: Channel, conversation_id: str) -> str | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT active_task_id FROM channel_sessions WHERE user_id=? AND source=? "
                "AND conversation_id=?",
                (user_id, source.value, conversation_id),
            ).fetchone()
        return row["active_task_id"] if row else None

    def begin_action(
        self,
        *,
        task_id: str,
        tool_name: str,
        idempotency_key: str,
        dry_run: bool,
        risk_level: RiskLevel,
        reason: str,
        input_data: dict[str, Any],
    ) -> tuple[str, dict[str, Any] | None]:
        now = utc_now()
        action_id = str(uuid.uuid4())
        with self._lock, self._connection() as connection:
            existing = connection.execute(
                "SELECT action_id, status, result_json FROM actions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if existing:
                result = (
                    json.loads(existing["result_json"])
                    if existing["result_json"]
                    else {"status": existing["status"]}
                )
                return existing["action_id"], result
            connection.execute(
                "INSERT INTO actions(action_id, task_id, tool_name, idempotency_key, dry_run, "
                "risk_level, reason, input_json, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'started', ?, ?)",
                (
                    action_id,
                    task_id,
                    tool_name,
                    idempotency_key,
                    int(dry_run),
                    risk_level.value,
                    reason,
                    json.dumps(input_data),
                    now,
                    now,
                ),
            )
        return action_id, None

    def finish_action(self, action_id: str, *, status: str, result: dict[str, Any]) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE actions SET status=?, result_json=?, updated_at=? WHERE action_id=?",
                (status, json.dumps(result), utc_now(), action_id),
            )

    def create_scheduled_job(
        self, *, task_id: str, kind: str, run_at: str, payload: dict[str, Any]
    ) -> str:
        job_id = str(uuid.uuid4())
        now = utc_now()
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO scheduled_jobs(job_id, task_id, kind, run_at, payload_json, status, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'scheduled', ?, ?)",
                (job_id, task_id, kind, run_at, json.dumps(payload), now, now),
            )
        return job_id

    def list_scheduled_jobs(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM scheduled_jobs ORDER BY run_at").fetchall()
        return [
            {
                **dict(row),
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def cancel_scheduled_job(self, job_id: str, *, task_id: str) -> None:
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "UPDATE scheduled_jobs SET status='cancelled', updated_at=? "
                "WHERE job_id=? AND task_id=? AND status='scheduled'",
                (utc_now(), job_id, task_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(job_id)

    def materialize_due_notifications(self) -> int:
        now = datetime.now(UTC)
        created = 0
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                "SELECT jobs.*, tasks.source, tasks.conversation_id "
                "FROM scheduled_jobs AS jobs JOIN tasks USING(task_id) "
                "WHERE jobs.status='scheduled' ORDER BY jobs.run_at"
            ).fetchall()
            for row in rows:
                run_at = datetime.fromisoformat(row["run_at"])
                if run_at.tzinfo is None:
                    run_at = run_at.replace(tzinfo=UTC)
                if run_at.astimezone(UTC) > now:
                    continue
                payload = json.loads(row["payload_json"])
                notification_id = str(uuid.uuid4())
                timestamp = utc_now()
                connection.execute(
                    "INSERT OR IGNORE INTO notifications(notification_id, job_id, source, "
                    "conversation_id, text, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
                    (
                        notification_id,
                        row["job_id"],
                        row["source"],
                        row["conversation_id"],
                        f"{payload.get('label', 'リマインダー')}の時間です。",
                        timestamp,
                        timestamp,
                    ),
                )
                for provider, target in sorted(self._notification_delivery_targets):
                    connection.execute(
                        "INSERT OR IGNORE INTO notification_deliveries("
                        "delivery_id, notification_id, provider, target, status, created_at, "
                        "updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                        (
                            str(uuid.uuid4()),
                            notification_id,
                            provider,
                            target,
                            timestamp,
                            timestamp,
                        ),
                    )
                connection.execute(
                    "UPDATE scheduled_jobs SET status='triggered', updated_at=? WHERE job_id=?",
                    (timestamp, row["job_id"]),
                )
                recurrence = payload.get("recurrence")
                if isinstance(recurrence, dict):
                    interval = int(recurrence.get("interval", 1))
                    frequency = recurrence.get("frequency")
                    delta = (
                        timedelta(days=interval)
                        if frequency == "daily"
                        else timedelta(weeks=interval)
                        if frequency == "weekly"
                        else None
                    )
                    count = recurrence.get("count")
                    next_count = int(count) - 1 if count is not None else None
                    next_at = run_at + delta if delta else None
                    until = recurrence.get("until")
                    within_until = not until or (
                        next_at is not None and next_at <= datetime.fromisoformat(until)
                    )
                    should_schedule = (
                        next_at is not None
                        and (next_count is None or next_count > 0)
                        and within_until
                    )
                    if should_schedule:
                        next_payload = dict(payload)
                        next_payload["recurrence"] = {
                            **recurrence,
                            "count": next_count,
                        }
                        next_job_id = str(uuid.uuid4())
                        connection.execute(
                            "INSERT INTO scheduled_jobs "
                            "(job_id, task_id, kind, run_at, payload_json, status, "
                            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'scheduled', ?, ?)",
                            (
                                next_job_id,
                                row["task_id"],
                                row["kind"],
                                next_at.isoformat(),
                                json.dumps(next_payload),
                                timestamp,
                                timestamp,
                            ),
                        )
                created += 1
        return created

    def configure_notification_delivery(self, *, provider: str, target: str) -> None:
        provider = provider.strip().casefold()
        target = target.strip()
        if not provider or not target:
            raise ValueError("Notification provider and target are required")
        now = utc_now()
        with self._lock, self._connection() as connection:
            self._notification_delivery_targets.add((provider, target))
            rows = connection.execute(
                "SELECT notification_id FROM notifications "
                "WHERE status IN ('pending', 'delivering')"
            ).fetchall()
            for row in rows:
                connection.execute(
                    "INSERT OR IGNORE INTO notification_deliveries("
                    "delivery_id, notification_id, provider, target, status, created_at, "
                    "updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                    (str(uuid.uuid4()), row["notification_id"], provider, target, now, now),
                )

    def claim_notification_delivery(
        self, *, provider: str, target: str
    ) -> dict[str, Any] | None:
        self.materialize_due_notifications()
        now = datetime.now(UTC)
        now_text = now.isoformat(timespec="milliseconds")
        lease_expires_at = (now + timedelta(seconds=30)).isoformat(timespec="milliseconds")
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE notification_deliveries SET status='pending', lease_expires_at=NULL, "
                "updated_at=? WHERE provider=? AND target=? AND status='delivering' AND "
                "(lease_expires_at IS NULL OR lease_expires_at < ?)",
                (now_text, provider, target, now_text),
            )
            row = connection.execute(
                "SELECT deliveries.*, notifications.job_id, notifications.text, jobs.task_id "
                "FROM notification_deliveries AS deliveries "
                "JOIN notifications USING(notification_id) "
                "JOIN scheduled_jobs AS jobs USING(job_id) "
                "WHERE deliveries.provider=? AND deliveries.target=? "
                "AND deliveries.status='pending' "
                "AND (deliveries.next_attempt_at IS NULL OR deliveries.next_attempt_at <= ?) "
                "ORDER BY deliveries.created_at LIMIT 1",
                (provider, target, now_text),
            ).fetchone()
            if row is None:
                return None
            cursor = connection.execute(
                "UPDATE notification_deliveries SET status='delivering', attempts=attempts+1, "
                "lease_expires_at=?, updated_at=? WHERE delivery_id=? AND status='pending'",
                (lease_expires_at, now_text, row["delivery_id"]),
            )
            if cursor.rowcount != 1:
                return None
        return {
            **dict(row),
            "status": "delivering",
            "attempts": int(row["attempts"]) + 1,
            "lease_expires_at": lease_expires_at,
        }

    def complete_notification_delivery(
        self,
        delivery_id: str,
        *,
        status: str,
        external_id: str | None = None,
        error: str | None = None,
    ) -> None:
        if status not in {"delivered", "failed", "submitted_unknown"}:
            raise ValueError("Invalid terminal notification delivery status")
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "UPDATE notification_deliveries SET status=?, lease_expires_at=NULL, "
                "next_attempt_at=NULL, external_id=?, last_error=?, updated_at=? "
                "WHERE delivery_id=? AND status='delivering'",
                (status, external_id, error, utc_now(), delivery_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(delivery_id)

    def retry_notification_delivery(
        self, delivery_id: str, *, delay_seconds: int, error: str
    ) -> None:
        next_attempt_at = (datetime.now(UTC) + timedelta(seconds=delay_seconds)).isoformat(
            timespec="milliseconds"
        )
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "UPDATE notification_deliveries SET status='pending', lease_expires_at=NULL, "
                "next_attempt_at=?, last_error=?, updated_at=? "
                "WHERE delivery_id=? AND status='delivering'",
                (next_attempt_at, error, utc_now(), delivery_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(delivery_id)

    def claim_notification(self, *, source: str, conversation_id: str) -> dict[str, Any] | None:
        self.materialize_due_notifications()
        now = datetime.now(UTC)
        now_text = now.isoformat(timespec="milliseconds")
        lease_expires_at = (now + timedelta(seconds=30)).isoformat(timespec="milliseconds")
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE notifications SET status='pending', lease_expires_at=NULL, updated_at=? "
                "WHERE status='delivering' AND "
                "(lease_expires_at IS NULL OR lease_expires_at < ?)",
                (now_text, now_text),
            )
            row = connection.execute(
                "SELECT * FROM notifications WHERE status='pending' AND source=? "
                "AND conversation_id=? ORDER BY created_at LIMIT 1",
                (source, conversation_id),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE notifications SET status='delivering', lease_expires_at=?, updated_at=? "
                "WHERE notification_id=? AND status='pending'",
                (lease_expires_at, now_text, row["notification_id"]),
            )
        return {**dict(row), "status": "delivering", "lease_expires_at": lease_expires_at}

    def acknowledge_notification(self, notification_id: str) -> None:
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "UPDATE notifications SET status='delivered', lease_expires_at=NULL, updated_at=? "
                "WHERE notification_id=? AND status='delivering'",
                (utc_now(), notification_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(notification_id)

    def release_notification(self, notification_id: str) -> None:
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "UPDATE notifications SET status='pending', lease_expires_at=NULL, updated_at=? "
                "WHERE notification_id=? AND status='delivering'",
                (utc_now(), notification_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(notification_id)

    def append_audit(
        self,
        *,
        task_id: str | None,
        actor: str,
        action: str,
        result: str,
        details: dict[str, Any],
    ) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO audit_events(task_id, actor, action, result, "
                "details_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (task_id, actor, action, result, json.dumps(details), utc_now()),
            )

    def claim_inbound_event(self, *, source: str, external_event_id: str) -> bool:
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO inbound_events(source, external_event_id, "
                "status, created_at) "
                "VALUES (?, ?, 'received', ?)",
                (source, external_event_id, utc_now()),
            )
            return cursor.rowcount == 1

    @staticmethod
    def arguments_hash(arguments: dict[str, Any]) -> str:
        encoded = json.dumps(
            arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def request_approval(
        self,
        *,
        task_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        input_summary: dict[str, Any],
        risk_level: RiskLevel,
        reason: str,
    ) -> dict[str, Any]:
        approval_id = str(uuid.uuid4())
        digest = self.arguments_hash(arguments)
        now = utc_now()
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO approvals "
                "(approval_id, task_id, tool_name, arguments_hash, input_summary_json, "
                "risk_level, reason, state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                (
                    approval_id,
                    task_id,
                    tool_name,
                    digest,
                    json.dumps(input_summary, ensure_ascii=False),
                    risk_level.value,
                    reason,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM approvals WHERE task_id = ? AND tool_name = ? "
                "AND arguments_hash = ?",
                (task_id, tool_name, digest),
            ).fetchone()
        return self._approval_from_row(row)

    def approval_for_action(
        self, *, task_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        digest = self.arguments_hash(arguments)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE task_id = ? AND tool_name = ? "
                "AND arguments_hash = ?",
                (task_id, tool_name, digest),
            ).fetchone()
        return self._approval_from_row(row) if row else None

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        if row is None:
            raise KeyError(approval_id)
        return self._approval_from_row(row)

    def decide_approval(
        self,
        approval_id: str,
        *,
        approved: bool,
        actor: str,
        method: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT state, risk_level FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise KeyError(approval_id)
            if row["state"] != "pending":
                raise ValueError("Approval has already been decided")
            if approved and row["risk_level"] in {RiskLevel.R4.value, RiskLevel.R5.value}:
                raise PermissionError("R4/R5 approval requires a strong-auth provider")
            connection.execute(
                "UPDATE approvals SET state = ?, decision_actor = ?, decision_method = ?, "
                "decided_at = ?, updated_at = ? WHERE approval_id = ?",
                (
                    "approved" if approved else "denied",
                    actor,
                    method,
                    now,
                    now,
                    approval_id,
                ),
            )
            result = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        return self._approval_from_row(result)

    def consume_approval(self, approval_id: str) -> bool:
        now = utc_now()
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "UPDATE approvals SET state = 'consumed', consumed_at = ?, updated_at = ? "
                "WHERE approval_id = ? AND state = 'approved'",
                (now, now, approval_id),
            )
            return cursor.rowcount == 1

    def list_approvals(self, *, state: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self._connection() as connection:
            if state:
                rows = connection.execute(
                    "SELECT * FROM approvals WHERE state = ? ORDER BY created_at DESC LIMIT ?",
                    (state, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [self._approval_from_row(row) for row in rows]

    def list_audit(self, *, query: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self._connection() as connection:
            if query and query.strip():
                pattern = f"%{query.strip()}%"
                rows = connection.execute(
                    "SELECT * FROM audit_events WHERE actor LIKE ? OR action LIKE ? "
                    "OR result LIKE ? OR details_json LIKE ? "
                    "ORDER BY audit_id DESC LIMIT ?",
                    (pattern, pattern, pattern, pattern, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM audit_events ORDER BY audit_id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def get_setting(self, key: str) -> Any:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT value_json FROM settings WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row["value_json"])

    def settings_snapshot(self) -> dict[str, Any]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT key, value_json, version, updated_at FROM settings ORDER BY key"
            ).fetchall()
        return {
            row["key"]: {
                "value": json.loads(row["value_json"]),
                "version": row["version"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        }

    def set_setting(self, key: str, value: Any) -> None:
        now = utc_now()
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO settings(key, value_json, version, updated_at) VALUES (?, ?, 1, ?) "
                "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, "
                "version=settings.version+1, updated_at=excluded.updated_at",
                (key, json.dumps(value), now),
            )

    def set_safety_lock(self, key: str, enabled: bool) -> int:
        """Update a safety lock and bump the policy version in one transaction."""
        allowed = {"global_pause", "finance_lock", "browser_lock", "secret_lock"}
        if key not in allowed:
            raise KeyError(key)
        now = utc_now()
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE settings SET value_json=?, version=version+1, updated_at=? WHERE key=?",
                (json.dumps(enabled), now, key),
            )
            row = connection.execute(
                "SELECT value_json FROM settings WHERE key='policy_version'"
            ).fetchone()
            policy_version = int(json.loads(row["value_json"])) + 1
            connection.execute(
                "UPDATE settings SET value_json=?, version=version+1, updated_at=? "
                "WHERE key='policy_version'",
                (json.dumps(policy_version), now),
            )
        return policy_version

    @staticmethod
    def _task_from_row(row: sqlite3.Row) -> TaskRecord:
        return TaskRecord(
            task_id=row["task_id"],
            user_id=row["user_id"],
            goal=row["goal"],
            state=TaskState(row["state"]),
            risk_level=RiskLevel(row["risk_level"]),
            route=Route(row["route"]) if row["route"] else None,
            source=Channel(row["source"]),
            conversation_id=row["conversation_id"],
            plan=json.loads(row["plan_json"]),
            result=json.loads(row["result_json"]) if row["result_json"] else None,
            error=row["error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _approval_from_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["input_summary"] = json.loads(result.pop("input_summary_json"))
        return result
