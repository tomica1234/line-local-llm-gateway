from __future__ import annotations

import json
import uuid
from typing import Any

from ..approval import canonical_json
from ..memory.sanitizer import sanitize_payload, sanitize_text
from ..storage import Storage, utc_now
from .models import Candidate, CommerceKind, CommerceQuote, CommerceState, ConfirmationEvidence

COMMERCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS commerce_workflows (
    workflow_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    goal TEXT NOT NULL,
    constraints_json TEXT NOT NULL,
    candidates_json TEXT NOT NULL,
    selected_candidate_id TEXT,
    final_quote_json TEXT,
    quote_hash TEXT,
    state TEXT NOT NULL,
    submit_idempotency_key TEXT UNIQUE,
    confirmation_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_commerce_task_state
ON commerce_workflows(task_id, state, updated_at DESC);
"""


class CommerceStore:
    def __init__(self, storage: Storage):
        self.storage = storage

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(COMMERCE_SCHEMA)

    def create(
        self,
        *,
        task_id: str,
        kind: CommerceKind,
        goal: str,
        constraints: dict[str, Any],
    ) -> dict[str, Any]:
        workflow_id = str(uuid.uuid4())
        safe_goal, _ = sanitize_text(goal)
        safe_constraints, _ = sanitize_payload(constraints)
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO commerce_workflows "
                "(workflow_id, task_id, kind, goal, constraints_json, candidates_json, state, "
                "confirmation_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, '[]', 'SEARCHING', '{}', ?, ?)",
                (
                    workflow_id,
                    task_id,
                    kind.value,
                    safe_goal,
                    json.dumps(safe_constraints, ensure_ascii=False),
                    now,
                    now,
                ),
            )
        return self.get(workflow_id)

    def set_candidates(self, workflow_id: str, candidates: list[Candidate]) -> dict[str, Any]:
        current = self.get(workflow_id)
        if current["state"] not in {"SEARCHING", "COMPARING"}:
            raise ValueError("Candidates cannot be replaced after selection")
        identifiers = [candidate.candidate_id for candidate in candidates]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Candidate IDs must be unique")
        safe, _ = sanitize_payload([item.model_dump(mode="json") for item in candidates])
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE commerce_workflows SET candidates_json=?, state='COMPARING', "
                "updated_at=? WHERE workflow_id=?",
                (json.dumps(safe, ensure_ascii=False), utc_now(), workflow_id),
            )
        return self.get(workflow_id)

    def select(self, workflow_id: str, candidate_id: str) -> dict[str, Any]:
        current = self.get(workflow_id)
        if current["state"] != "COMPARING":
            raise ValueError("A workflow must be comparing candidates before selection")
        if candidate_id not in {item["candidate_id"] for item in current["candidates"]}:
            raise KeyError(candidate_id)
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE commerce_workflows SET selected_candidate_id=?, state='SELECTED', "
                "updated_at=? WHERE workflow_id=?",
                (candidate_id, utc_now(), workflow_id),
            )
        return self.get(workflow_id)

    def set_quote(self, workflow_id: str, quote: CommerceQuote) -> dict[str, Any]:
        current = self.get(workflow_id)
        if current["state"] not in {"SELECTED", "QUOTED"}:
            raise ValueError("Select a candidate before fixing the final quote")
        payload = quote.model_dump(mode="json")
        import hashlib

        quote_hash = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE commerce_workflows SET final_quote_json=?, quote_hash=?, "
                "state='QUOTED', confirmation_json='{}', updated_at=? WHERE workflow_id=?",
                (json.dumps(payload, ensure_ascii=False), quote_hash, utc_now(), workflow_id),
            )
        return self.get(workflow_id)

    def record_submission(
        self,
        *,
        workflow_id: str,
        task_id: str,
        idempotency_key: str,
        browser_verified: bool,
        confirmation_number: str | None,
        booking_id: str | None,
    ) -> dict[str, Any]:
        current = self.get(workflow_id)
        if current["task_id"] != task_id:
            raise PermissionError("Commerce workflow is owned by another task")
        if current["state"] == CommerceState.CONFIRMED.value:
            return current
        if current["submit_idempotency_key"]:
            if current["submit_idempotency_key"] != idempotency_key:
                raise PermissionError("A submitted workflow cannot be submitted again")
            return current
        if current["state"] != CommerceState.QUOTED.value or not current["final_quote"]:
            raise ValueError("An exact final quote is required before submission")
        evidence = ConfirmationEvidence(
            browser_verified=browser_verified,
            confirmation_number=confirmation_number,
            booking_id=booking_id,
        ).model_dump(mode="json")
        state = (
            CommerceState.PENDING_RECONCILIATION
            if browser_verified and (confirmation_number or booking_id)
            else CommerceState.SUBMITTED_UNKNOWN
        )
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE commerce_workflows SET submit_idempotency_key=?, confirmation_json=?, "
                "state=?, updated_at=? WHERE workflow_id=?",
                (
                    idempotency_key,
                    json.dumps(evidence, ensure_ascii=False),
                    state.value,
                    utc_now(),
                    workflow_id,
                ),
            )
        return self.get(workflow_id)

    def reconcile(self, workflow_id: str, evidence: ConfirmationEvidence) -> dict[str, Any]:
        current = self.get(workflow_id)
        if current["state"] not in {
            CommerceState.PENDING_RECONCILIATION.value,
            CommerceState.SUBMITTED_UNKNOWN.value,
        }:
            raise ValueError("Workflow is not awaiting reconciliation")
        existing = ConfirmationEvidence.model_validate(current["confirmation"])
        merged = existing.model_copy(
            update={
                key: value
                for key, value in evidence.model_dump().items()
                if value not in {None, False}
            }
        )
        quote = CommerceQuote.model_validate(current["final_quote"])
        browser_id = merged.confirmation_number or merged.booking_id
        email_matches = bool(
            browser_id
            and merged.email_confirmation_number
            and browser_id.casefold() == merged.email_confirmation_number.casefold()
        )
        amount_matches = merged.observed_total in {None, quote.total}
        currency_matches = merged.observed_currency in {None, quote.currency}
        durable_second_source = email_matches or bool(merged.receipt_path)
        confirmed = bool(
            merged.browser_verified
            and browser_id
            and durable_second_source
            and amount_matches
            and currency_matches
        )
        state = CommerceState.CONFIRMED if confirmed else CommerceState.SUBMITTED_UNKNOWN
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE commerce_workflows SET confirmation_json=?, state=?, updated_at=? "
                "WHERE workflow_id=?",
                (
                    json.dumps(merged.model_dump(mode="json"), ensure_ascii=False),
                    state.value,
                    utc_now(),
                    workflow_id,
                ),
            )
        result = self.get(workflow_id)
        result["reconciliation"] = {
            "confirmed": confirmed,
            "email_matches": email_matches,
            "amount_matches": amount_matches,
            "currency_matches": currency_matches,
            "resent": False,
        }
        return result

    def get(self, workflow_id: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM commerce_workflows WHERE workflow_id=?", (workflow_id,)
            ).fetchone()
        if row is None:
            raise KeyError(workflow_id)
        result = dict(row)
        result["constraints"] = json.loads(result.pop("constraints_json"))
        result["candidates"] = json.loads(result.pop("candidates_json"))
        quote = result.pop("final_quote_json")
        result["final_quote"] = json.loads(quote) if quote else None
        result["confirmation"] = json.loads(result.pop("confirmation_json"))
        return result

    def list(self, *, task_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            if task_id:
                rows = connection.execute(
                    "SELECT workflow_id FROM commerce_workflows WHERE task_id=? "
                    "ORDER BY updated_at DESC LIMIT ?",
                    (task_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT workflow_id FROM commerce_workflows ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [self.get(row["workflow_id"]) for row in rows]
