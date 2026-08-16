from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from personal_agent.backup import EncryptedBackupService


class ReversingProtector:
    name = "test-reversing"

    def protect(self, plaintext: bytes) -> bytes:
        return plaintext[::-1]

    def unprotect(self, ciphertext: bytes) -> bytes:
        return ciphertext[::-1]


def test_encrypted_backup_round_trip_and_recoverable_replace(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE notes(value TEXT)")
        connection.execute("INSERT INTO notes VALUES ('durable')")
    backup = tmp_path / "backup.pab"
    service = EncryptedBackupService(ReversingProtector())

    metadata = service.create(source, backup)
    assert metadata["protector"] == "test-reversing"
    assert b"durable" not in backup.read_bytes()
    assert service.inspect(backup)["plaintext_sha256"] == metadata["plaintext_sha256"]

    restored = tmp_path / "restored.sqlite3"
    result = service.restore(backup, restored)
    assert result["integrity"] == "ok"
    with sqlite3.connect(restored) as connection:
        assert connection.execute("SELECT value FROM notes").fetchone()[0] == "durable"

    with pytest.raises(FileExistsError, match="explicit replace"):
        service.restore(backup, restored)
    replaced = service.restore(backup, restored, replace=True)
    assert Path(str(replaced["previous_database"])).exists()


def test_backup_rejects_overwrite_and_invalid_format(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE test(value INTEGER)")
    destination = tmp_path / "existing.pab"
    destination.write_text("do not overwrite", encoding="utf-8")
    service = EncryptedBackupService(ReversingProtector())

    with pytest.raises(FileExistsError):
        service.create(source, destination)
    with pytest.raises(ValueError, match="Not a Personal Agent"):
        service.inspect(destination)
