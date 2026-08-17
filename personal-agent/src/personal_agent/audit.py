from __future__ import annotations

from typing import Any

from .redaction import redact
from .storage import Storage


class AuditLogger:
    def __init__(self, storage: Storage):
        self.storage = storage

    def record(
        self,
        *,
        task_id: str | None,
        actor: str,
        action: str,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.storage.append_audit(
            task_id=task_id,
            actor=actor,
            action=action,
            result=result,
            details=redact(details or {}),
        )
