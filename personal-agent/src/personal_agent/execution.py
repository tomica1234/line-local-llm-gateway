from __future__ import annotations

import hashlib
import json
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from .core.capabilities import CapabilityStep
from .storage import Storage, utc_now
from .types import RiskLevel, TaskState

EXECUTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS execution_plans (
    plan_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id) ON DELETE CASCADE,
    goal_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_steps (
    plan_id TEXT NOT NULL REFERENCES execution_plans(plan_id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    step_id TEXT NOT NULL,
    step_order INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    allowed_tools_json TEXT NOT NULL,
    permissions_json TEXT NOT NULL,
    risk TEXT NOT NULL,
    status TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    output_json TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT,
    completed_at TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    model TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(plan_id, step_id)
);
CREATE INDEX IF NOT EXISTS idx_execution_steps_task
ON execution_steps(task_id, step_order);
CREATE INDEX IF NOT EXISTS idx_execution_steps_status
ON execution_steps(status, updated_at);
"""


class ExecutionStepStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    WAITING_AUTH = "WAITING_AUTH"
    WAITING_USER = "WAITING_USER"
    WAITING_EXTERNAL = "WAITING_EXTERNAL"
    SUBMITTED_UNKNOWN = "SUBMITTED_UNKNOWN"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ExecutionStepRecord(BaseModel):
    plan_id: str
    task_id: str
    step_id: str
    step_order: int
    purpose: str
    allowed_tools: list[str]
    permissions: list[str]
    risk: RiskLevel
    status: ExecutionStepStatus
    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    started_at: str | None = None
    completed_at: str | None = None
    attempt: int
    model: str
    prompt_version: str
    updated_at: str

    def capability(self) -> CapabilityStep:
        return CapabilityStep(
            step_id=self.step_id,
            purpose=self.purpose,
            allowed_tools=frozenset(self.allowed_tools),
            permissions=frozenset(self.permissions),
            risk=self.risk,
        )


class ExecutionStore:
    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(EXECUTION_SCHEMA)

    def ensure_plan(
        self,
        *,
        task_id: str,
        goal: str,
        steps: tuple[CapabilityStep, ...],
        model: str,
        prompt_version: str,
    ) -> str:
        goal_hash = hashlib.sha256(goal.encode("utf-8")).hexdigest()
        with self.storage.transaction() as connection:
            existing = connection.execute(
                "SELECT plan_id, goal_hash FROM execution_plans WHERE task_id=?", (task_id,)
            ).fetchone()
            if existing:
                if existing["goal_hash"] != goal_hash:
                    raise ValueError("A durable execution plan cannot be rebound to another goal")
                return str(existing["plan_id"])
            plan_id = str(uuid.uuid4())
            now = utc_now()
            connection.execute(
                "INSERT INTO execution_plans(plan_id, task_id, goal_hash, status, model, "
                "prompt_version, created_at, updated_at) VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?, ?)",
                (plan_id, task_id, goal_hash, model, prompt_version, now, now),
            )
            for order, step in enumerate(steps, start=1):
                connection.execute(
                    "INSERT INTO execution_steps(plan_id, task_id, step_id, step_order, "
                    "purpose, allowed_tools_json, permissions_json, risk, status, input_json, "
                    "evidence_json, model, prompt_version, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', '{}', '{}', ?, ?, ?)",
                    (
                        plan_id,
                        task_id,
                        step.step_id,
                        order,
                        step.purpose,
                        json.dumps(sorted(step.allowed_tools)),
                        json.dumps(sorted(step.permissions)),
                        step.risk.value,
                        model,
                        prompt_version,
                        now,
                    ),
                )
        return plan_id

    def steps(self, task_id: str) -> list[ExecutionStepRecord]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM execution_steps WHERE task_id=? ORDER BY step_order", (task_id,)
            ).fetchall()
        return [self._record(row) for row in rows]

    def start_step(self, task_id: str, step_id: str, *, input_data: dict[str, Any]) -> None:
        now = utc_now()
        resumable = (
            "'PENDING','WAITING_APPROVAL','WAITING_AUTH','WAITING_USER','WAITING_EXTERNAL','FAILED'"
        )
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "UPDATE execution_steps SET status='RUNNING', input_json=?, started_at=?, "
                "completed_at=NULL, attempt=attempt+1, updated_at=? WHERE task_id=? AND step_id=? "
                f"AND status IN ({resumable})",
                (json.dumps(input_data, ensure_ascii=False), now, now, task_id, step_id),
            )
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT status FROM execution_steps WHERE task_id=? AND step_id=?",
                    (task_id, step_id),
                ).fetchone()
                if row is None:
                    raise KeyError(step_id)
                if row["status"] != ExecutionStepStatus.COMPLETED.value:
                    raise ValueError(f"Step {step_id} is not resumable from {row['status']}")

    def set_status(
        self,
        task_id: str,
        step_id: str,
        status: ExecutionStepStatus,
        *,
        output: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        terminal = status in {
            ExecutionStepStatus.COMPLETED,
            ExecutionStepStatus.FAILED,
            ExecutionStepStatus.CANCELLED,
            ExecutionStepStatus.SUBMITTED_UNKNOWN,
        }
        now = utc_now()
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "UPDATE execution_steps SET status=?, output_json=?, evidence_json=?, "
                "completed_at=?, updated_at=? WHERE task_id=? AND step_id=?",
                (
                    status.value,
                    json.dumps(output, ensure_ascii=False) if output is not None else None,
                    json.dumps(evidence or {}, ensure_ascii=False),
                    now if terminal else None,
                    now,
                    task_id,
                    step_id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(step_id)
            plan_id = connection.execute(
                "SELECT plan_id FROM execution_steps WHERE task_id=? AND step_id=?",
                (task_id, step_id),
            ).fetchone()["plan_id"]
            remaining = connection.execute(
                "SELECT COUNT(*) AS count FROM execution_steps WHERE plan_id=? "
                "AND status!='COMPLETED'",
                (plan_id,),
            ).fetchone()["count"]
            plan_status = (
                "COMPLETED"
                if remaining == 0
                else "BLOCKED"
                if status
                in {
                    ExecutionStepStatus.SUBMITTED_UNKNOWN,
                    ExecutionStepStatus.WAITING_APPROVAL,
                    ExecutionStepStatus.WAITING_AUTH,
                    ExecutionStepStatus.WAITING_USER,
                    ExecutionStepStatus.WAITING_EXTERNAL,
                }
                else "ACTIVE"
            )
            connection.execute(
                "UPDATE execution_plans SET status=?, updated_at=? WHERE plan_id=?",
                (plan_status, now, plan_id),
            )

    def cancel_task(self, task_id: str) -> None:
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE execution_steps SET status='CANCELLED', completed_at=?, updated_at=? "
                "WHERE task_id=? AND status NOT IN ('COMPLETED','CANCELLED','SUBMITTED_UNKNOWN')",
                (now, now, task_id),
            )
            connection.execute(
                "UPDATE execution_plans SET status='CANCELLED', updated_at=? WHERE task_id=?",
                (now, task_id),
            )

    def recover_incomplete(self) -> dict[str, int]:
        """Recover reads safely and fail closed for an in-flight external mutation."""

        recovered = 0
        submitted_unknown = 0
        now = utc_now()
        with self.storage.transaction() as connection:
            rows = connection.execute(
                "SELECT task_id, step_id FROM execution_steps WHERE status='RUNNING'"
            ).fetchall()
            for row in rows:
                mutation = connection.execute(
                    "SELECT 1 FROM actions WHERE task_id=? AND step_id=? AND mutation=1 "
                    "AND status='started' LIMIT 1",
                    (row["task_id"], row["step_id"]),
                ).fetchone()
                if mutation:
                    status = ExecutionStepStatus.SUBMITTED_UNKNOWN
                    task_state = TaskState.SUBMITTED_UNKNOWN
                    submitted_unknown += 1
                else:
                    status = ExecutionStepStatus.PENDING
                    task_state = TaskState.PAUSED
                    recovered += 1
                connection.execute(
                    "UPDATE execution_steps SET status=?, completed_at=?, updated_at=? "
                    "WHERE task_id=? AND step_id=?",
                    (
                        status.value,
                        now if status is ExecutionStepStatus.SUBMITTED_UNKNOWN else None,
                        now,
                        row["task_id"],
                        row["step_id"],
                    ),
                )
                connection.execute(
                    "UPDATE tasks SET state=?, updated_at=? WHERE task_id=?",
                    (task_state.value, now, row["task_id"]),
                )
        return {"resumable": recovered, "submitted_unknown": submitted_unknown}

    @staticmethod
    def _record(row: Any) -> ExecutionStepRecord:
        value = dict(row)
        value["allowed_tools"] = json.loads(value.pop("allowed_tools_json"))
        value["permissions"] = json.loads(value.pop("permissions_json"))
        value["input"] = json.loads(value.pop("input_json"))
        value["output"] = json.loads(value.pop("output_json")) if value["output_json"] else None
        value.pop("output_json", None)
        value["evidence"] = json.loads(value.pop("evidence_json"))
        return ExecutionStepRecord.model_validate(value)
