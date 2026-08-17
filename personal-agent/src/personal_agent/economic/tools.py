from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..approval import ApprovalMaterial
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
    def economic_material(args: BaseModel) -> ApprovalMaterial:
        parsed = IntentIdArgs.model_validate(args)
        intent = store.intent(parsed.economic_intent_id)
        quote = intent.get("final_quote") or {}
        payload = {
            "provider_or_site": intent.get("provider"),
            "item_or_service": quote.get("item") or intent.get("target"),
            "quantity": quote.get("quantity"),
            "seller": quote.get("seller"),
            "unit_price": quote.get("unit_price"),
            "shipping": quote.get("shipping"),
            "fee": quote.get("fees"),
            "tax": (intent.get("conditions") or {}).get("tax"),
            "total": quote.get("total") or intent.get("amount"),
            "currency": quote.get("currency") or intent.get("currency"),
            "delivery_or_reservation_date": quote.get("delivery_at"),
            "cancellation_policy": (
                quote.get("cancellation_policy") or intent.get("cancellation_policy")
            ),
            "payment_method_reference": intent.get("payment_method_ref"),
            "economic_intent_id": parsed.economic_intent_id,
        }
        return ApprovalMaterial.create(
            action_type="economic.execute_sandbox",
            title=f"{intent.get('action_type', 'economic')}を確定",
            human_summary=(
                f"{payload['total']} {payload['currency']} の表示条件で1回だけ実行します。"
            ),
            structured_payload=payload,
        )

    def transfer_material(args: BaseModel) -> ApprovalMaterial:
        parsed = IntentIdArgs.model_validate(args)
        intent = store.intent(parsed.economic_intent_id)
        quote = intent.get("final_quote") or {}
        payee = store.payee(str(quote.get("payee_id") or intent.get("target")))
        payload = {
            "payee_display_name": payee["display_name"],
            "payee_id": payee["payee_id"],
            "amount": quote.get("amount") or intent.get("amount"),
            "currency": quote.get("currency") or intent.get("currency"),
            "fee": quote.get("fee", "0"),
            "purpose": quote.get("purpose") or (intent.get("conditions") or {}).get("purpose"),
            "economic_intent_id": parsed.economic_intent_id,
        }
        return ApprovalMaterial.create(
            action_type="money.execute_transfer_sandbox",
            title=f"{payee['display_name']}へのsandbox送金",
            human_summary=f"{payload['amount']} {payload['currency']}をsandboxで送金します。",
            structured_payload=payload,
        )

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
            required_permissions=("economic.prepare",),
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
            required_permissions=("economic.prepare",),
        ),
        ToolDefinition(
            name="economic.execute_sandbox",
            description="Execute a policy-checked economic intent in the sandbox only.",
            args_model=IntentIdArgs,
            handler=execute,
            risk_level=RiskLevel.R3,
            mutation=True,
            required_permissions=("economic.execute",),
            approval_material_builder=economic_material,
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
            required_permissions=("economic.prepare",),
        ),
        ToolDefinition(
            name="money.execute_transfer_sandbox",
            description="Execute an approved transfer against the dedicated sandbox balance.",
            args_model=IntentIdArgs,
            handler=execute_transfer,
            risk_level=RiskLevel.R3,
            mutation=True,
            required_permissions=("economic.execute",),
            approval_material_builder=transfer_material,
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
            required_permissions=("economic.read",),
        ),
    ]
