from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Literal

from .models import BrowserProfile


def _now() -> str:
    return datetime.now(UTC).isoformat()


class BrowserWorkerStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = Lock()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS browser_actions (
                    profile TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    state TEXT NOT NULL,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (profile, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS browser_sessions (
                    profile TEXT PRIMARY KEY,
                    url TEXT,
                    state TEXT NOT NULL,
                    task_id TEXT,
                    takeover_reason TEXT,
                    takeover_started_at TEXT,
                    takeover_expires_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS browser_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile TEXT NOT NULL,
                    task_id TEXT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    auth_session_id TEXT PRIMARY KEY,
                    profile TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    account_label TEXT,
                    factor TEXT,
                    field_ref TEXT,
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connector_oauth_sessions (
                    session_id TEXT PRIMARY KEY,
                    state_hash TEXT NOT NULL UNIQUE,
                    task_id TEXT NOT NULL,
                    client_id_credential_id TEXT NOT NULL,
                    client_secret_credential_id TEXT NOT NULL,
                    refresh_credential_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    account_label TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_connector_oauth_expiry
                ON connector_oauth_sessions(consumed_at, expires_at);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def begin_action(
        self,
        *,
        profile: BrowserProfile,
        idempotency_key: str,
        task_id: str,
        action_id: str,
        action: str,
    ) -> tuple[Literal["new", "duplicate", "in_progress"], dict[str, Any] | None]:
        timestamp = _now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state, result_json, task_id, action_id, action FROM browser_actions "
                "WHERE profile = ? AND idempotency_key = ?",
                (profile.value, idempotency_key),
            ).fetchone()
            if row:
                if (
                    row["task_id"] != task_id
                    or row["action_id"] != action_id
                    or row["action"] != action
                ):
                    raise ValueError("Idempotency key was already used for another action")
                if row["state"] == "completed" and row["result_json"]:
                    return "duplicate", json.loads(row["result_json"])
                return "in_progress", None
            connection.execute(
                "INSERT INTO browser_actions "
                "(profile, idempotency_key, task_id, action_id, action, state, "
                "created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'running', ?, ?)",
                (
                    profile.value,
                    idempotency_key,
                    task_id,
                    action_id,
                    action,
                    timestamp,
                    timestamp,
                ),
            )
            return "new", None

    def finish_action(
        self,
        *,
        profile: BrowserProfile,
        idempotency_key: str,
        result: dict[str, Any],
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE browser_actions SET state = 'completed', result_json = ?, updated_at = ? "
                "WHERE profile = ? AND idempotency_key = ?",
                (json.dumps(result, ensure_ascii=False), _now(), profile.value, idempotency_key),
            )

    def update_session(
        self,
        profile: BrowserProfile,
        *,
        url: str | None,
        state: str,
        task_id: str | None = None,
        reason: str | None = None,
        started_at: str | None = None,
        expires_at: str | None = None,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO browser_sessions "
                "(profile, url, state, task_id, takeover_reason, takeover_started_at, "
                "takeover_expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(profile) DO UPDATE SET url=excluded.url, state=excluded.state, "
                "task_id=excluded.task_id, takeover_reason=excluded.takeover_reason, "
                "takeover_started_at=excluded.takeover_started_at, "
                "takeover_expires_at=excluded.takeover_expires_at, updated_at=excluded.updated_at",
                (
                    profile.value,
                    url,
                    state,
                    task_id,
                    reason,
                    started_at,
                    expires_at,
                    _now(),
                ),
            )

    def sessions(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM browser_sessions ORDER BY profile").fetchall()
        return [dict(row) for row in rows]

    def record_audit(
        self,
        *,
        profile: BrowserProfile,
        task_id: str | None,
        actor: str,
        action: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO browser_audit "
                "(profile, task_id, actor, action, result, details_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    profile.value,
                    task_id,
                    actor,
                    action,
                    result,
                    json.dumps(details or {}, ensure_ascii=False),
                    _now(),
                ),
            )

    def audit(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM browser_audit ORDER BY audit_id DESC LIMIT ?", (limit,)
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            result.append(item)
        return result

    def put_auth_session(self, session: dict[str, Any]) -> None:
        timestamp = _now()
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO auth_sessions "
                "(auth_session_id, profile, task_id, origin, account_label, factor, "
                "field_ref, state, attempts, max_attempts, expires_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(auth_session_id) DO UPDATE SET factor=excluded.factor, "
                "field_ref=excluded.field_ref, state=excluded.state, "
                "attempts=excluded.attempts, max_attempts=excluded.max_attempts, "
                "expires_at=excluded.expires_at, updated_at=excluded.updated_at",
                (
                    session["auth_session_id"],
                    session["profile"],
                    session["task_id"],
                    session["origin"],
                    session.get("account_label"),
                    session.get("factor"),
                    session.get("field_ref"),
                    session["state"],
                    session.get("attempts", 0),
                    session.get("max_attempts", 3),
                    session.get("expires_at"),
                    session.get("created_at", timestamp),
                    timestamp,
                ),
            )

    def get_auth_session(self, auth_session_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM auth_sessions WHERE auth_session_id = ?",
                (auth_session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(auth_session_id)
        return dict(row)

    def list_auth_sessions(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM auth_sessions ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def put_oauth_session(
        self,
        *,
        session_id: str,
        state: str,
        task_id: str,
        client_id_credential_id: str,
        client_secret_credential_id: str,
        refresh_credential_id: str,
        redirect_uri: str,
        scopes: list[str],
        account_label: str,
        ttl_seconds: int = 600,
    ) -> None:
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=ttl_seconds)
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM connector_oauth_sessions WHERE expires_at < ? OR "
                "consumed_at IS NOT NULL",
                (now.isoformat(),),
            )
            connection.execute(
                "INSERT INTO connector_oauth_sessions(session_id, state_hash, task_id, "
                "client_id_credential_id, client_secret_credential_id, "
                "refresh_credential_id, redirect_uri, scopes_json, account_label, "
                "expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    hashlib.sha256(state.encode()).hexdigest(),
                    task_id,
                    client_id_credential_id,
                    client_secret_credential_id,
                    refresh_credential_id,
                    redirect_uri,
                    json.dumps(scopes),
                    account_label,
                    expires.isoformat(),
                    now.isoformat(),
                ),
            )

    def consume_oauth_session(self, state: str) -> dict[str, Any]:
        now = datetime.now(UTC)
        digest = hashlib.sha256(state.encode()).hexdigest()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM connector_oauth_sessions WHERE state_hash=? "
                "AND consumed_at IS NULL AND expires_at>=?",
                (digest, now.isoformat()),
            ).fetchone()
            if row is None:
                raise PermissionError("OAuth state is invalid, expired, or already consumed")
            connection.execute(
                "UPDATE connector_oauth_sessions SET consumed_at=? WHERE session_id=? "
                "AND consumed_at IS NULL",
                (now.isoformat(), row["session_id"]),
            )
        result = dict(row)
        result["scopes"] = json.loads(result.pop("scopes_json"))
        result.pop("state_hash", None)
        return result
