from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..types import RiskLevel


class EconomicAction(StrEnum):
    PURCHASE = "purchase"
    RESERVE = "reserve"
    SUBSCRIBE = "subscribe"
    CANCEL = "cancel"
    REFUND = "refund"
    RETURN = "return"
    PAY_BILL = "pay_bill"
    TRANSFER = "transfer"


class ExecutionState(StrEnum):
    CREATED = "CREATED"
    RESOLVED = "RESOLVED"
    POLICY_CHECKED = "POLICY_CHECKED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    SUBMITTED = "SUBMITTED"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    SUBMITTED_UNKNOWN = "SUBMITTED_UNKNOWN"
    CANCELLED = "CANCELLED"


class EconomicIntentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: EconomicAction
    target: str = Field(min_length=1, max_length=1_000)
    provider: str = Field(min_length=1, max_length=500)
    amount: Decimal = Field(gt=0, max_digits=18, decimal_places=2)
    currency: str = Field(default="JPY", pattern=r"^[A-Z]{3}$")
    budget: str = Field(default="personal", min_length=1, max_length=100)
    conditions: dict[str, Any] = Field(default_factory=dict)
    cancellation_policy: str = Field(default="unknown", max_length=10_000)
    payment_method_ref: str | None = Field(
        default=None, pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$"
    )
    risk_level: RiskLevel = RiskLevel.R3


class FinalQuote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item: str = Field(min_length=1, max_length=2_000)
    quantity: int = Field(default=1, ge=1, le=1_000)
    unit_price: Decimal = Field(gt=0, max_digits=18, decimal_places=2)
    shipping: Decimal = Field(default=Decimal("0"), ge=0, max_digits=18, decimal_places=2)
    fees: Decimal = Field(default=Decimal("0"), ge=0, max_digits=18, decimal_places=2)
    total: Decimal = Field(gt=0, max_digits=18, decimal_places=2)
    currency: str = Field(default="JPY", pattern=r"^[A-Z]{3}$")
    seller: str = Field(min_length=1, max_length=1_000)
    delivery_at: str | None = None
    cancellation_policy: str = Field(min_length=1, max_length=10_000)
    cancellable: bool
    source_reference: str = Field(min_length=1, max_length=2_000)

    @field_validator("total")
    @classmethod
    def total_must_cover_components(cls, value: Decimal, info: Any) -> Decimal:
        data = info.data
        if {"quantity", "unit_price", "shipping", "fees"}.issubset(data):
            expected = data["unit_price"] * data["quantity"] + data["shipping"] + data["fees"]
            if value != expected:
                raise ValueError("Quote total does not equal item, shipping, and fees")
        return value


class PayeeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payee_id: str = Field(pattern=r"^payee_[a-z0-9_-]{3,100}$")
    display_name: str = Field(min_length=1, max_length=500)
    aliases: list[str] = Field(default_factory=list, max_length=100)
    entity_id: str = Field(min_length=1, max_length=128)
    trusted: bool = False
    payment_route_ref: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    per_transfer_limit: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    daily_limit: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    monthly_limit: Decimal = Field(ge=0, max_digits=18, decimal_places=2)


class TransferIntentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payee_id: str = Field(pattern=r"^payee_[a-z0-9_-]{3,100}$")
    amount: Decimal = Field(gt=0, max_digits=18, decimal_places=2)
    currency: str = Field(default="JPY", pattern=r"^[A-Z]{3}$")
    purpose: str = Field(min_length=1, max_length=1_000)


class BudgetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str = Field(min_length=1, max_length=100)
    currency: str = Field(default="JPY", pattern=r"^[A-Z]{3}$")
    per_action_limit: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    daily_limit: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    monthly_limit: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
