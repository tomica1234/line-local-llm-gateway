from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .models import Candidate, CommerceKind, CommerceQuote, ConfirmationEvidence
from .store import CommerceStore


class CreateArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: CommerceKind
    goal: str = Field(min_length=1, max_length=2_000)
    constraints: dict[str, Any] = Field(default_factory=dict)


class CandidatesArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_id: str
    candidates: list[Candidate] = Field(min_length=1, max_length=20)


class SelectArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_id: str
    candidate_id: str


class QuoteArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_id: str
    quote: CommerceQuote


class SubmissionArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_id: str
    browser_verified: bool
    confirmation_number: str | None = Field(default=None, max_length=200)
    booking_id: str | None = Field(default=None, max_length=200)


class ReconcileArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_id: str
    evidence: ConfirmationEvidence


class WorkflowIdArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_id: str


def commerce_tools(store: CommerceStore) -> list[ToolDefinition[Any]]:
    def create(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = CreateArgs.model_validate(args)
        item = store.create(
            task_id=context.task_id,
            kind=parsed.kind,
            goal=parsed.goal,
            constraints=parsed.constraints,
        )
        return ToolResult(status="ok", external_id=item["workflow_id"], evidence={"workflow": item})

    def candidates(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = CandidatesArgs.model_validate(args)
        item = store.set_candidates(parsed.workflow_id, parsed.candidates)
        return ToolResult(status="ok", external_id=item["workflow_id"], evidence={"workflow": item})

    def select(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = SelectArgs.model_validate(args)
        item = store.select(parsed.workflow_id, parsed.candidate_id)
        return ToolResult(status="ok", external_id=item["workflow_id"], evidence={"workflow": item})

    def quote(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = QuoteArgs.model_validate(args)
        item = store.set_quote(parsed.workflow_id, parsed.quote)
        return ToolResult(
            status="ok",
            external_id=item["workflow_id"],
            evidence={"workflow": item, "next_action": "browser.submit_with_exact_quote"},
        )

    def submission(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = SubmissionArgs.model_validate(args)
        item = store.record_submission(
            workflow_id=parsed.workflow_id,
            task_id=context.task_id,
            idempotency_key=context.idempotency_key,
            browser_verified=parsed.browser_verified,
            confirmation_number=parsed.confirmation_number,
            booking_id=parsed.booking_id,
        )
        unknown = item["state"] == "SUBMITTED_UNKNOWN"
        return ToolResult(
            status="submitted_unknown" if unknown else "ok",
            external_id=item["workflow_id"],
            evidence={"workflow": item, "resent": False},
            next_action="commerce.reconcile" if unknown else "commerce.reconcile_confirmation",
        )

    def reconcile(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ReconcileArgs.model_validate(args)
        item = store.reconcile(parsed.workflow_id, parsed.evidence)
        confirmed = bool(item["reconciliation"]["confirmed"])
        return ToolResult(
            status="ok" if confirmed else "submitted_unknown",
            external_id=item["workflow_id"],
            evidence={"workflow": item, "resent": False},
            next_action=None if confirmed else "manual_reconciliation",
        )

    def get(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = WorkflowIdArgs.model_validate(args)
        return ToolResult(status="ok", evidence={"workflow": store.get(parsed.workflow_id)})

    definitions = [
        ("commerce.create", CreateArgs, create, RiskLevel.R1, True, "commerce.prepare"),
        (
            "commerce.set_candidates",
            CandidatesArgs,
            candidates,
            RiskLevel.R1,
            True,
            "commerce.prepare",
        ),
        ("commerce.select", SelectArgs, select, RiskLevel.R1, True, "commerce.prepare"),
        ("commerce.set_final_quote", QuoteArgs, quote, RiskLevel.R1, True, "commerce.prepare"),
        (
            "commerce.record_submission",
            SubmissionArgs,
            submission,
            RiskLevel.R1,
            True,
            "commerce.reconcile",
        ),
        (
            "commerce.reconcile",
            ReconcileArgs,
            reconcile,
            RiskLevel.R0,
            True,
            "commerce.reconcile",
        ),
        ("commerce.get", WorkflowIdArgs, get, RiskLevel.R0, False, "commerce.read"),
    ]
    return [
        ToolDefinition(
            name=name,
            description=(
                "Durable shopping/reservation workflow operation; it never submits a browser "
                "mutation or retries an unknown submission by itself."
            ),
            args_model=args_model,
            handler=handler,
            risk_level=risk,
            mutation=mutation,
            required_permissions=(permission,),
        )
        for name, args_model, handler, risk, mutation, permission in definitions
    ]
