from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from .secret.protection import SecretProtector

_MAGIC = b"PERSONAL-AGENT-BACKUP\x00v1\n"


class EncryptedBackupService:
    def __init__(self, protector: SecretProtector):
        self.protector = protector

    def create(self, source: Path, destination: Path) -> dict[str, object]:
        source = source.resolve(strict=True)
        destination = destination.resolve(strict=False)
        self._validate_local_path(destination)
        if destination.exists():
            raise FileExistsError("Backup destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            prefix=".personal-agent-backup-",
            suffix=".sqlite3",
            dir=destination.parent,
            delete=False,
        ) as handle:
            snapshot_path = Path(handle.name)
        try:
            with sqlite3.connect(source) as source_connection:
                with sqlite3.connect(snapshot_path) as snapshot_connection:
                    source_connection.backup(snapshot_connection)
            plaintext = snapshot_path.read_bytes()
            digest = hashlib.sha256(plaintext).hexdigest()
            ciphertext = self.protector.protect(plaintext)
            metadata = {
                "format": "personal-agent-backup-v1",
                "created_at": datetime.now(UTC).isoformat(),
                "protector": self.protector.name,
                "plaintext_sha256": digest,
                "plaintext_bytes": len(plaintext),
            }
            encoded_metadata = json.dumps(metadata, separators=(",", ":")).encode()
            payload = (
                _MAGIC + struct.pack(">I", len(encoded_metadata)) + encoded_metadata + ciphertext
            )
            self._atomic_write(destination, payload)
            return {
                **metadata,
                "destination": str(destination),
                "encrypted_bytes": len(payload),
            }
        finally:
            snapshot_path.unlink(missing_ok=True)

    def inspect(self, backup: Path) -> dict[str, object]:
        metadata, _ = self._read(backup)
        return metadata

    def restore(
        self,
        backup: Path,
        destination: Path,
        *,
        replace: bool = False,
    ) -> dict[str, object]:
        destination = destination.resolve(strict=False)
        self._validate_local_path(destination)
        metadata, ciphertext = self._read(backup)
        plaintext = self.protector.unprotect(ciphertext)
        digest = hashlib.sha256(plaintext).hexdigest()
        if digest != metadata.get("plaintext_sha256"):
            raise ValueError("Backup integrity digest does not match")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            prefix=".personal-agent-restore-",
            suffix=".sqlite3",
            dir=destination.parent,
            delete=False,
        ) as handle:
            restore_path = Path(handle.name)
            handle.write(plaintext)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            with sqlite3.connect(restore_path) as connection:
                check = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            if check != "ok":
                raise ValueError(f"Restored SQLite integrity check failed: {check}")
            previous_path = None
            if destination.exists():
                if not replace:
                    raise FileExistsError(
                        "Restore destination exists; explicit replace confirmation is required"
                    )
                sidecars = [
                    Path(f"{destination}-wal"),
                    Path(f"{destination}-shm"),
                ]
                if any(path.exists() for path in sidecars):
                    raise RuntimeError(
                        "Stop Personal Agent and remove/checkpoint SQLite WAL sidecars "
                        "before restore"
                    )
                stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
                previous_path = destination.with_name(f"{destination.name}.pre-restore-{stamp}")
                if previous_path.exists():
                    raise FileExistsError("Pre-restore recovery path already exists")
                destination.replace(previous_path)
            os.replace(restore_path, destination)
            try:
                destination.chmod(0o600)
            except OSError:
                pass
            return {
                "status": "restored",
                "destination": str(destination),
                "previous_database": str(previous_path) if previous_path else None,
                "integrity": check,
                "plaintext_sha256": digest,
            }
        finally:
            restore_path.unlink(missing_ok=True)

    @staticmethod
    def _read(backup: Path) -> tuple[dict[str, object], bytes]:
        payload = backup.resolve(strict=True).read_bytes()
        if not payload.startswith(_MAGIC):
            raise ValueError("Not a Personal Agent encrypted backup")
        offset = len(_MAGIC)
        if len(payload) < offset + 4:
            raise ValueError("Backup header is truncated")
        metadata_length = struct.unpack(">I", payload[offset : offset + 4])[0]
        offset += 4
        if metadata_length > 64_000 or len(payload) <= offset + metadata_length:
            raise ValueError("Backup metadata length is invalid")
        try:
            metadata = json.loads(payload[offset : offset + metadata_length])
        except json.JSONDecodeError as exc:
            raise ValueError("Backup metadata is invalid") from exc
        ciphertext = payload[offset + metadata_length :]
        return metadata, ciphertext

    @staticmethod
    def _atomic_write(destination: Path, payload: bytes) -> None:
        with tempfile.NamedTemporaryFile(
            prefix=".personal-agent-encrypted-",
            dir=destination.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _validate_local_path(path: Path) -> None:
        if os.name == "nt" and str(path).startswith("\\\\"):
            raise ValueError("Encrypted backups cannot be written to a network share")
