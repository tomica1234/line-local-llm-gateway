from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..secret.models import SecretAction
from ..types import RiskLevel


class BrowserProfile(StrEnum):
    GENERAL = "general"
    COMMUNICATION = "communication"
    SHOPPING = "shopping"
    TRAVEL = "travel"
    FINANCE = "finance"
    ADMINISTRATION = "administration"


class BrowserAction(StrEnum):
    OPEN = "open"
    SNAPSHOT = "snapshot"
    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    CHECK = "check"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    TABS = "tabs"
    NEW_TAB = "new_tab"
    CLOSE_TAB = "close_tab"
    SWITCH_TAB = "switch_tab"
    BACK = "back"
    FORWARD = "forward"
    RELOAD = "reload"
    HOVER = "hover"
    PRESS = "press"
    SCROLL = "scroll"
    SUBMIT = "submit"
    WAIT = "wait"
    SCREENSHOT = "screenshot"
    CLICK_POINT = "click_point"
    GET_URL = "get_url"
    GET_DOWNLOADS = "get_downloads"


READ_ONLY_ACTIONS = {
    BrowserAction.SNAPSHOT,
    BrowserAction.TABS,
    BrowserAction.SCREENSHOT,
    BrowserAction.GET_URL,
    BrowserAction.GET_DOWNLOADS,
}
MUTATION_ACTIONS = set(BrowserAction) - READ_ONLY_ACTIONS


class ActionContext(BaseModel):
    task_id: str = Field(min_length=1, max_length=128)
    action_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=256)
    dry_run: bool = False
    reason: str = Field(min_length=1, max_length=1_000)
    risk_level: RiskLevel = RiskLevel.R0


class BrowserActionRequest(BaseModel):
    params: dict[str, Any] = Field(default_factory=dict)
    context: ActionContext | None = None


class StrictParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OpenParams(StrictParams):
    url: str = Field(min_length=1, max_length=8_192)


class RefParams(StrictParams):
    ref: str = Field(pattern=r"^ref-[1-9][0-9]*$")


class TypeParams(RefParams):
    text: str = Field(max_length=20_000)
    clear: bool = True


class SelectParams(RefParams):
    values: list[str] = Field(min_length=1, max_length=50)


class CheckParams(RefParams):
    checked: bool = True


class UploadParams(RefParams):
    paths: list[str] = Field(min_length=1, max_length=20)


class DownloadParams(RefParams):
    timeout_ms: int = Field(default=30_000, ge=1_000, le=120_000)


class SwitchTabParams(StrictParams):
    index: int = Field(ge=0, le=100)


class PressParams(RefParams):
    key: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9+_-]+$",
    )


class ScrollParams(StrictParams):
    delta_x: float = Field(default=0, ge=-10_000, le=10_000)
    delta_y: float = Field(default=0, ge=-10_000, le=10_000)

    @model_validator(mode="after")
    def require_movement(self) -> ScrollParams:
        if self.delta_x == 0 and self.delta_y == 0:
            raise ValueError("At least one scroll delta must be non-zero")
        return self


class TransactionApproval(StrictParams):
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
    def require_exact_total(self) -> TransactionApproval:
        expected = self.unit_price * self.quantity + self.shipping + self.fee + self.tax
        if expected != self.total:
            raise ValueError("Transaction total does not match its components")
        return self


class SubmitParams(RefParams):
    # Core-originated submits always provide these approval fields. Defaults preserve
    # compatibility for direct worker recovery tests; the worker never grants approval.
    origin: str = Field(default="", max_length=2_000)
    page_title: str = Field(default="", max_length=500)
    action_target: str = Field(default="", max_length=500)
    submit_target: str = Field(default="", max_length=500)
    nonsecret_inputs: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=100
    )
    transaction: TransactionApproval | None = None
    expected_text: str | None = Field(default=None, min_length=2, max_length=200)
    expected_url_prefix: str | None = Field(default=None, min_length=10, max_length=2_000)
    timeout_ms: int = Field(default=10_000, ge=500, le=30_000)

    @model_validator(mode="after")
    def require_postcondition(self) -> SubmitParams:
        if not self.expected_text and not self.expected_url_prefix:
            raise ValueError("A submit postcondition is required")
        return self


class WaitParams(StrictParams):
    timeout_ms: int = Field(default=1_000, ge=0, le=60_000)
    ref: str | None = Field(default=None, pattern=r"^ref-[1-9][0-9]*$")


class ScreenshotParams(StrictParams):
    full_page: bool = False


class ClickPointParams(StrictParams):
    x: float = Field(ge=0, le=100_000)
    y: float = Field(ge=0, le=100_000)
    target: str = Field(min_length=1, max_length=500)


class EmptyParams(StrictParams):
    pass


ACTION_PARAMETER_MODELS: dict[BrowserAction, type[BaseModel]] = {
    BrowserAction.OPEN: OpenParams,
    BrowserAction.SNAPSHOT: EmptyParams,
    BrowserAction.CLICK: RefParams,
    BrowserAction.TYPE: TypeParams,
    BrowserAction.SELECT: SelectParams,
    BrowserAction.CHECK: CheckParams,
    BrowserAction.UPLOAD: UploadParams,
    BrowserAction.DOWNLOAD: DownloadParams,
    BrowserAction.TABS: EmptyParams,
    BrowserAction.NEW_TAB: EmptyParams,
    BrowserAction.CLOSE_TAB: EmptyParams,
    BrowserAction.SWITCH_TAB: SwitchTabParams,
    BrowserAction.BACK: EmptyParams,
    BrowserAction.FORWARD: EmptyParams,
    BrowserAction.RELOAD: EmptyParams,
    BrowserAction.HOVER: RefParams,
    BrowserAction.PRESS: PressParams,
    BrowserAction.SCROLL: ScrollParams,
    BrowserAction.SUBMIT: SubmitParams,
    BrowserAction.WAIT: WaitParams,
    BrowserAction.SCREENSHOT: ScreenshotParams,
    BrowserAction.CLICK_POINT: ClickPointParams,
    BrowserAction.GET_URL: EmptyParams,
    BrowserAction.GET_DOWNLOADS: EmptyParams,
}


class TakeoverStartRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1_000)
    context: ActionContext
    timeout_seconds: int | None = Field(default=None, ge=30, le=1_800)


class TakeoverReleaseRequest(BaseModel):
    outcome: Literal["completed", "cancelled"]


class SecretFillRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_ref: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    ref: str = Field(pattern=r"^ref-[1-9][0-9]*$")
    action: SecretAction
    context: ActionContext


class BrowserResult(BaseModel):
    status: Literal[
        "ok",
        "duplicate",
        "dry_run",
        "denied",
        "error",
        "human_required",
        "auth_required",
        "submitted_unknown",
    ]
    profile: BrowserProfile
    action: str
    result: dict[str, Any] = Field(default_factory=dict)
    signals: list[dict[str, str]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
