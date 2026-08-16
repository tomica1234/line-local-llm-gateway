from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .models import EconomicIntentCreate, FinalQuote, TransferIntentCreate
from .store import EconomicStore


class IntentArgs(EconomicIntentCreate):
    pass


class QuoteArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    economic_intent_id: str = Field(min_length=1, max_length=128)
    quote: FinalQuote


class IntentIdArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    economic_intent_id: str = Field(min_length=1, max_length=128)


class TransferArgs(TransferIntentCreate):
    pass


class TransactionIdArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_id: str = Field(min_length=1, max_length=128)


def economic_tools(store: EconomicStore) -> list[ToolDefinition[Any]]:
    def create_intent(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = IntentArgs.model_validate(args)
        intent = store.create_intent(
            task_id=context.task_id,
            intent=EconomicIntentCreate.model_validate(parsed.model_dump()),
        )
        return ToolResult(
            status="ok",
            external_id=intent["economic_intent_id"],
            reversible=True,
            evidence={"intent": intent, "executed": False},
        )

    def quote(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = QuoteArgs.model_validate(args)
        intent = store.set_final_quote(parsed.economic_intent_id, parsed.quote)
        return ToolResult(
            status="ok",
            external_id=intent["economic_intent_id"],
            reversible=True,
            evidence={
                "intent": intent,
                "final_details_verified": True,
                "executed": False,
            },
        )

    def execute(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = IntentIdArgs.model_validate(args)
        intent = store.execute_sandbox(
            task_id=context.task_id,
            intent_id=parsed.economic_intent_id,
            idempotency_key=context.idempotency_key,
        )
        evidence = intent["evidence"]
        return ToolResult(
            status="ok" if evidence.get("verified") else "submitted_unknown",
            external_id=evidence.get("external_id"),
            evidence={"intent": intent, "sandbox": True, "verified": evidence.get("verified")},
            next_action=None if evidence.get("verified") else "reconcile_before_retry",
        )

    def transfer_intent(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = TransferArgs.model_validate(args)
        intent = store.create_transfer_intent(
            task_id=context.task_id,
            transfer=TransferIntentCreate.model_validate(parsed.model_dump()),
        )
        return ToolResult(
            status="ok",
            external_id=intent["economic_intent_id"],
            evidence={
                "intent": intent,
                "account_details_exposed": False,
                "executed": False,
            },
        )

    def execute_transfer(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = IntentIdArgs.model_validate(args)
        transaction = store.execute_transfer_sandbox(
            task_id=context.task_id,
            intent_id=parsed.economic_intent_id,
            idempotency_key=context.idempotency_key,
        )
        return ToolResult(
            status=("ok" if transaction["state"] == "CONFIRMED" else "submitted_unknown"),
            external_id=transaction["external_id"],
            evidence={"transaction": transaction, "sandbox": True},
            next_action=(None if transaction["state"] == "CONFIRMED" else "money.reconcile"),
        )

    def reconcile(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = TransactionIdArgs.model_validate(args)
        result = store.reconcile(parsed.transaction_id)
        return ToolResult(
            status="ok" if result["matched"] else "submitted_unknown",
            external_id=result["transaction"]["external_id"],
            evidence=result,
            next_action=None if result["matched"] else "manual_reconciliation",
        )

    return [
        ToolDefinition(
            name="economic.create_intent",
            description="Create a structured shopping/reservation intent without executing it.",
            args_model=IntentArgs,
            handler=create_intent,
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="economic.set_final_quote",
            description=(
                "Bind exact item, quantity, price, shipping, seller, delivery and cancellation "
                "details and enforce the configured budget before execution."
            ),
            args_model=QuoteArgs,
            handler=quote,
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="economic.execute_sandbox",
            description="Execute a policy-checked economic intent in the sandbox only.",
            args_model=IntentIdArgs,
            handler=execute,
            risk_level=RiskLevel.R3,
            mutation=True,
        ),
        ToolDefinition(
            name="money.create_transfer_intent",
            description=(
                "Create a transfer intent for an exact registered payee_id; never accepts account "
                "or routing numbers."
            ),
            args_model=TransferArgs,
            handler=transfer_intent,
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="money.execute_transfer_sandbox",
            description="Execute an approved transfer against the dedicated sandbox balance.",
            args_model=IntentIdArgs,
            handler=execute_transfer,
            risk_level=RiskLevel.R3,
            mutation=True,
        ),
        ToolDefinition(
            name="money.reconcile",
            description=(
                "Reconcile a transaction by external ID, payee, amount and currency without "
                "resending it."
            ),
            args_model=TransactionIdArgs,
            handler=reconcile,
            risk_level=RiskLevel.R0,
        ),
    ]
