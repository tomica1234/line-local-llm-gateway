from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .memory import MemoryStore
from .memory.models import PreferenceUpsert
from .memory.sanitizer import sanitize_payload
from .storage import Storage, utc_now
from .tool_broker.broker import ToolContext, ToolDefinition
from .types import RiskLevel, ToolResult

LEARNING_SCHEMA = """
CREATE TABLE IF NOT EXISTS preference_candidates (
    candidate_id TEXT PRIMARY KEY,
    preference_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_event_ids_json TEXT NOT NULL,
    rationale TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(preference_key, value_json, state)
);
CREATE TABLE IF NOT EXISTS workflow_candidates (
    workflow_id TEXT PRIMARY KEY,
    signature TEXT NOT NULL UNIQUE,
    tool_sequence_json TEXT NOT NULL,
    occurrences INTEGER NOT NULL,
    source_task_ids_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_SECRET_KEY_PARTS = {
    "password",
    "secret",
    "token",
    "otp",
    "totp",
    "cookie",
    "card",
    "account_number",
}


class PreferenceCandidateArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    value: Any
    confidence: float = Field(ge=0, le=1)
    evidence_event_ids: list[str] = Field(min_length=1, max_length=100)
    rationale: str = Field(min_length=1, max_length=2_000)


class LearningService:
    def __init__(self, storage: Storage, memory: MemoryStore, *, user_id: str):
        self.storage = storage
        self.memory = memory
        self.user_id = user_id

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(LEARNING_SCHEMA)

    def propose_preference(self, proposal: PreferenceCandidateArgs) -> dict[str, Any]:
        lowered_key = proposal.key.casefold()
        if any(part in lowered_key for part in _SECRET_KEY_PARTS):
            raise PermissionError("Secret-like values cannot become preference candidates")
        self.memory._validate_evidence(self.user_id, proposal.evidence_event_ids)
        safe_value, redacted = sanitize_payload(proposal.value)
        if redacted:
            raise PermissionError("Redacted values cannot become preference candidates")
        candidate_id = str(uuid.uuid4())
        now = utc_now()
        encoded = json.dumps(safe_value, ensure_ascii=False, sort_keys=True)
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO preference_candidates "
                "(candidate_id, preference_key, value_json, confidence, "
                "evidence_event_ids_json, rationale, state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?, ?)",
                (
                    candidate_id,
                    proposal.key,
                    encoded,
                    proposal.confidence,
                    json.dumps(proposal.evidence_event_ids),
                    proposal.rationale,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM preference_candidates WHERE preference_key=? "
                "AND value_json=? AND state='proposed'",
                (proposal.key, encoded),
            ).fetchone()
        return self._preference_row(row)

    def decide_preference(self, candidate_id: str, *, accepted: bool) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM preference_candidates WHERE candidate_id=?",
                (candidate_id,),
            ).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        if row["state"] != "proposed":
            raise ValueError("Preference candidate has already been decided")
        if accepted:
            if float(row["confidence"]) < 0.6:
                raise ValueError(
                    "Low-confidence preferences require a new evidence-backed proposal"
                )
            self.memory.upsert_preference(
                user_id=self.user_id,
                preference=PreferenceUpsert(
                    key=row["preference_key"],
                    value=json.loads(row["value_json"]),
                    confidence=float(row["confidence"]),
                    evidence_event_ids=json.loads(row["evidence_event_ids_json"]),
                ),
            )
        state = "accepted" if accepted else "rejected"
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE preference_candidates SET state=?, updated_at=? "
                "WHERE candidate_id=? AND state='proposed'",
                (state, utc_now(), candidate_id),
            )
            decided = connection.execute(
                "SELECT * FROM preference_candidates WHERE candidate_id=?",
                (candidate_id,),
            ).fetchone()
        return self._preference_row(decided)

    def list_preferences(self, *, state: str | None = None) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            if state:
                rows = connection.execute(
                    "SELECT * FROM preference_candidates WHERE state=? ORDER BY created_at DESC",
                    (state,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM preference_candidates ORDER BY created_at DESC"
                ).fetchall()
        return [self._preference_row(row) for row in rows]

    def mine_workflows(self, *, minimum_occurrences: int = 3) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT a.task_id, a.tool_name FROM actions a JOIN tasks t USING(task_id) "
                "WHERE t.state='COMPLETED' AND a.status IN ('ok', 'duplicate') "
                "ORDER BY a.task_id, a.created_at"
            ).fetchall()
        sequences: dict[tuple[str, ...], list[str]] = defaultdict(list)
        current_task = None
        current_tools: list[str] = []
        for row in [*rows, {"task_id": None, "tool_name": None}]:
            if current_task is not None and row["task_id"] != current_task:
                sequence = tuple(current_tools)
                if len(sequence) >= 2:
                    sequences[sequence].append(current_task)
                current_tools = []
            current_task = row["task_id"]
            if row["tool_name"]:
                current_tools.append(row["tool_name"])
        created: list[dict[str, Any]] = []
        for sequence, task_ids in sequences.items():
            if len(task_ids) < minimum_occurrences:
                continue
            signature = hashlib.sha256("\0".join(sequence).encode()).hexdigest()
            workflow_id = str(uuid.uuid4())
            now = utc_now()
            with self.storage.transaction() as connection:
                connection.execute(
                    "INSERT INTO workflow_candidates "
                    "(workflow_id, signature, tool_sequence_json, occurrences, "
                    "source_task_ids_json, state, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 'proposed', ?, ?) "
                    "ON CONFLICT(signature) DO UPDATE SET "
                    "occurrences=excluded.occurrences, "
                    "source_task_ids_json=excluded.source_task_ids_json, "
                    "updated_at=excluded.updated_at",
                    (
                        workflow_id,
                        signature,
                        json.dumps(sequence),
                        len(task_ids),
                        json.dumps(task_ids),
                        now,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM workflow_candidates WHERE signature=?", (signature,)
                ).fetchone()
            created.append(self._workflow_row(row))
        return created

    def list_workflows(self) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM workflow_candidates ORDER BY occurrences DESC, created_at DESC"
            ).fetchall()
        return [self._workflow_row(row) for row in rows]

    def decide_workflow(self, workflow_id: str, *, accepted: bool) -> dict[str, Any]:
        state = "accepted_disabled" if accepted else "rejected"
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "UPDATE workflow_candidates SET state=?, updated_at=? "
                "WHERE workflow_id=? AND state='proposed'",
                (state, utc_now(), workflow_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(workflow_id)
            row = connection.execute(
                "SELECT * FROM workflow_candidates WHERE workflow_id=?", (workflow_id,)
            ).fetchone()
        return self._workflow_row(row)

    @staticmethod
    def _preference_row(row: Any) -> dict[str, Any]:
        result = dict(row)
        result["value"] = json.loads(result.pop("value_json"))
        result["evidence_event_ids"] = json.loads(result.pop("evidence_event_ids_json"))
        return result

    @staticmethod
    def _workflow_row(row: Any) -> dict[str, Any]:
        result = dict(row)
        result["tool_sequence"] = json.loads(result.pop("tool_sequence_json"))
        result["source_task_ids"] = json.loads(result.pop("source_task_ids_json"))
        return result


def learning_tools(service: LearningService) -> list[ToolDefinition[Any]]:
    def propose(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = PreferenceCandidateArgs.model_validate(args)
        candidate = service.propose_preference(parsed)
        return ToolResult(
            status="ok",
            reversible=True,
            evidence={
                "candidate_id": candidate["candidate_id"],
                "state": candidate["state"],
                "requires_user_confirmation": True,
            },
        )

    return [
        ToolDefinition(
            name="learning.propose_preference",
            description=(
                "Propose an evidence-backed preference candidate; never commits it directly."
            ),
            args_model=PreferenceCandidateArgs,
            handler=propose,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("learning.propose",),
        )
    ]
