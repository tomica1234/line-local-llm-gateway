from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import struct
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from urllib.parse import urlparse

from .models import SecretAction, SecretCreate, SecretKind, SecretMetadata
from .protection import SecretProtector


def _now() -> str:
    return datetime.now(UTC).isoformat()


def normalize_origin(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Allowed origin must be an http(s) URL with a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Origin must not contain credentials")
    hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    default_port = 80 if parsed.scheme == "http" else 443
    port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    return f"{parsed.scheme}://{hostname}{port}"


def totp_code(seed: str, *, now: int | None = None, digits: int = 6, period: int = 30) -> str:
    normalized = "".join(seed.split()).upper()
    try:
        key = base64.b32decode(normalized, casefold=True)
    except Exception as exc:
        raise ValueError("TOTP seed is not valid base32") from exc
    counter = int(time.time() if now is None else now) // period
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


class SecretStore:
    """Encrypted values and their use log live outside the Memory database."""

    def __init__(self, path: Path, protector: SecretProtector):
        self.path = path
        self.protector = protector
        self._lock = RLock()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    credential_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    account_label TEXT NOT NULL,
                    allowed_origins_json TEXT NOT NULL,
                    allowed_actions_json TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    protection_backend TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS secret_use_log (
                    use_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def put(self, create: SecretCreate, plaintext: str) -> SecretMetadata:
        if not plaintext:
            raise ValueError("Secret value must not be empty")
        origins = [normalize_origin(item) for item in create.allowed_origins]
        actions = [item.value for item in create.allowed_actions]
        compatible = {
            SecretKind.USERNAME: {SecretAction.USERNAME_FILL.value},
            SecretKind.PASSWORD: {SecretAction.PASSWORD_FILL.value},
            SecretKind.TOTP_SEED: {SecretAction.TOTP_FILL.value},
            SecretKind.API_TOKEN: {SecretAction.CONNECTOR_REQUEST.value},
        }
        if not set(actions).issubset(compatible[create.kind]):
            raise ValueError("Secret kind is incompatible with an allowed action")
        ciphertext = self.protector.protect(plaintext.encode("utf-8"))
        timestamp = _now()
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO credentials "
                "(credential_id, kind, account_label, allowed_origins_json, "
                "allowed_actions_json, ciphertext, protection_backend, enabled, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?) "
                "ON CONFLICT(credential_id) DO UPDATE SET kind=excluded.kind, "
                "account_label=excluded.account_label, "
                "allowed_origins_json=excluded.allowed_origins_json, "
                "allowed_actions_json=excluded.allowed_actions_json, "
                "ciphertext=excluded.ciphertext, protection_backend=excluded.protection_backend, "
                "enabled=1, updated_at=excluded.updated_at",
                (
                    create.credential_id,
                    create.kind.value,
                    create.account_label,
                    json.dumps(origins),
                    json.dumps(actions),
                    ciphertext,
                    self.protector.name,
                    timestamp,
                    timestamp,
                ),
            )
        return self.metadata(create.credential_id)

    def metadata(self, credential_id: str) -> SecretMetadata:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT credential_id, kind, account_label, allowed_origins_json, "
                "allowed_actions_json, enabled, created_at, updated_at, last_used_at "
                "FROM credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        if row is None:
            raise KeyError(credential_id)
        return self._metadata(row)

    def list_metadata(self) -> list[SecretMetadata]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT credential_id, kind, account_label, allowed_origins_json, "
                "allowed_actions_json, enabled, created_at, updated_at, last_used_at "
                "FROM credentials ORDER BY credential_id"
            ).fetchall()
        return [self._metadata(row) for row in rows]

    def value_for_use(
        self,
        *,
        credential_id: str,
        origin: str,
        action: SecretAction,
        task_id: str,
    ) -> str:
        if not task_id:
            raise ValueError("Secret use must be bound to a task")
        normalized_origin = normalize_origin(origin)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
            ).fetchone()
        if row is None:
            raise KeyError(credential_id)
        if not row["enabled"]:
            raise PermissionError("Credential is disabled")
        origins = json.loads(row["allowed_origins_json"])
        actions = json.loads(row["allowed_actions_json"])
        if normalized_origin not in origins:
            raise PermissionError("Credential is not allowed for this exact origin")
        if action.value not in actions:
            raise PermissionError("Credential is not allowed for this action")
        plaintext = self.protector.unprotect(bytes(row["ciphertext"])).decode("utf-8")
        if action is SecretAction.TOTP_FILL:
            plaintext = totp_code(plaintext)
        return plaintext

    def record_use(
        self,
        *,
        credential_id: str,
        task_id: str,
        origin: str,
        action: SecretAction,
        result: str,
    ) -> None:
        timestamp = _now()
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO secret_use_log "
                "(credential_id, task_id, origin, action, result, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (credential_id, task_id, normalize_origin(origin), action.value, result, timestamp),
            )
            if result == "ok":
                connection.execute(
                    "UPDATE credentials SET last_used_at = ?, updated_at = ? "
                    "WHERE credential_id = ?",
                    (timestamp, timestamp, credential_id),
                )

    def usage(self, *, limit: int = 200) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT credential_id, task_id, origin, action, result, created_at "
                "FROM secret_use_log ORDER BY use_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def disable(self, credential_id: str) -> None:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE credentials SET enabled = 0, updated_at = ? WHERE credential_id = ?",
                (_now(), credential_id),
            )
        if cursor.rowcount != 1:
            raise KeyError(credential_id)

    @staticmethod
    def _metadata(row: sqlite3.Row) -> SecretMetadata:
        return SecretMetadata(
            credential_id=row["credential_id"],
            kind=SecretKind(row["kind"]),
            account_label=row["account_label"],
            allowed_origins=json.loads(row["allowed_origins_json"]),
            allowed_actions=[
                SecretAction(item) for item in json.loads(row["allowed_actions_json"])
            ],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_used_at=row["last_used_at"],
        )
