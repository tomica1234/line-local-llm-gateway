from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CommerceKind(StrEnum):
    SHOPPING = "shopping"
    RESERVATION = "reservation"


class CommerceState(StrEnum):
    SEARCHING = "SEARCHING"
    COMPARING = "COMPARING"
    SELECTED = "SELECTED"
    QUOTED = "QUOTED"
    SUBMITTED = "SUBMITTED"
    PENDING_RECONCILIATION = "PENDING_RECONCILIATION"
    SUBMITTED_UNKNOWN = "SUBMITTED_UNKNOWN"
    CONFIRMED = "CONFIRMED"
    CANCELLED = "CANCELLED"


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(pattern=r"^candidate_[a-zA-Z0-9_-]{3,100}$")
    provider: str = Field(min_length=1, max_length=500)
    title: str = Field(min_length=1, max_length=2_000)
    source_reference: str = Field(min_length=1, max_length=2_000)
    price: Decimal | None = Field(default=None, ge=0, max_digits=18, decimal_places=2)
    currency: str = Field(default="JPY", pattern=r"^[A-Z]{3}$")
    attributes: dict[str, Any] = Field(default_factory=dict)


class CommerceQuote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_or_site: str = Field(min_length=1, max_length=500)
    item_or_service: str = Field(min_length=1, max_length=2_000)
    quantity: int = Field(default=1, ge=1, le=1_000)
    seller: str = Field(min_length=1, max_length=1_000)
    unit_price: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    shipping: Decimal = Field(default=Decimal("0"), ge=0, max_digits=18, decimal_places=2)
    fee: Decimal = Field(default=Decimal("0"), ge=0, max_digits=18, decimal_places=2)
    tax: Decimal = Field(default=Decimal("0"), ge=0, max_digits=18, decimal_places=2)
    total: Decimal = Field(gt=0, max_digits=18, decimal_places=2)
    currency: str = Field(default="JPY", pattern=r"^[A-Z]{3}$")
    delivery_or_reservation_date: str | None = Field(default=None, max_length=200)
    cancellation_policy: str = Field(min_length=1, max_length=10_000)
    payment_method_reference: str | None = Field(
        default=None, pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$"
    )

    @model_validator(mode="after")
    def exact_total(self) -> CommerceQuote:
        expected = self.unit_price * self.quantity + self.shipping + self.fee + self.tax
        if self.total != expected:
            raise ValueError("Final quote total does not match its components")
        return self


class ConfirmationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    browser_verified: bool = False
    confirmation_number: str | None = Field(default=None, max_length=200)
    booking_id: str | None = Field(default=None, max_length=200)
    email_confirmation_number: str | None = Field(default=None, max_length=200)
    email_message_id: str | None = Field(default=None, max_length=300)
    receipt_path: str | None = Field(default=None, max_length=2_000)
    calendar_event_id: str | None = Field(default=None, max_length=300)
    observed_total: Decimal | None = Field(default=None, ge=0, max_digits=18, decimal_places=2)
    observed_currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
