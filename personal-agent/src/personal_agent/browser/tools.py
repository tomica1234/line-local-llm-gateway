from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..approval import ApprovalMaterial
from ..browser_worker.models import (
    ActionContext,
    BrowserAction,
    BrowserProfile,
    TransactionApproval,
)
from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .client import BrowserWorkerClient


class BrowserArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: BrowserProfile = BrowserProfile.GENERAL


class OpenArgs(BrowserArgs):
    url: str = Field(min_length=1, max_length=8_192)


class RefArgs(BrowserArgs):
    ref: str = Field(pattern=r"^ref-[1-9][0-9]*$")


class TypeArgs(RefArgs):
    text: str = Field(max_length=20_000)
    clear: bool = True


class SelectArgs(RefArgs):
    values: list[str] = Field(min_length=1, max_length=50)


class CheckArgs(RefArgs):
    checked: bool = True


class UploadArgs(RefArgs):
    paths: list[str] = Field(min_length=1, max_length=20)


class DownloadArgs(RefArgs):
    timeout_ms: int = Field(default=30_000, ge=1_000, le=120_000)


class SwitchTabArgs(BrowserArgs):
    index: int = Field(ge=0, le=100)


class PressArgs(RefArgs):
    key: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9+_-]+$")


class ScrollArgs(BrowserArgs):
    delta_x: float = Field(default=0, ge=-10_000, le=10_000)
    delta_y: float = Field(default=0, ge=-10_000, le=10_000)

    @model_validator(mode="after")
    def require_movement(self) -> ScrollArgs:
        if self.delta_x == 0 and self.delta_y == 0:
            raise ValueError("At least one scroll delta must be non-zero")
        return self


class SubmitArgs(RefArgs):
    origin: str = Field(min_length=8, max_length=2_000)
    page_title: str = Field(min_length=1, max_length=500)
    action_target: str = Field(min_length=1, max_length=500)
    submit_target: str = Field(min_length=1, max_length=500)
    nonsecret_inputs: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=100
    )
    transaction: TransactionApproval | None = None
    expected_text: str | None = Field(default=None, min_length=2, max_length=200)
    expected_url_prefix: str | None = Field(default=None, min_length=10, max_length=2_000)
    timeout_ms: int = Field(default=10_000, ge=500, le=30_000)

    @field_validator("origin")
    @classmethod
    def origin_only(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Submit origin must be an absolute HTTP(S) origin")
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.hostname}{port}"

    @field_validator("nonsecret_inputs")
    @classmethod
    def reject_secret_fields(
        cls, value: dict[str, str | int | float | bool | None]
    ) -> dict[str, str | int | float | bool | None]:
        forbidden = ("password", "passwd", "secret", "token", "otp", "cookie", "card", "cvv")
        if any(any(word in key.casefold() for word in forbidden) for key in value):
            raise ValueError("Secret input metadata must not be included in approval material")
        return value

    @model_validator(mode="after")
    def require_postcondition(self) -> SubmitArgs:
        if not self.expected_text and not self.expected_url_prefix:
            raise ValueError("A submit postcondition is required")
        return self


class WaitArgs(BrowserArgs):
    timeout_ms: int = Field(default=1_000, ge=0, le=60_000)
    ref: str | None = Field(default=None, pattern=r"^ref-[1-9][0-9]*$")


class ScreenshotArgs(BrowserArgs):
    full_page: bool = False


class VisionArgs(BrowserArgs):
    prompt: str = Field(
        default="画面の内容を説明し、操作候補の位置を根拠付きで示してください",
        max_length=2_000,
    )


class ClickPointArgs(BrowserArgs):
    x: float = Field(ge=0, le=100_000)
    y: float = Field(ge=0, le=100_000)
    target: str = Field(min_length=1, max_length=500)


class EmptyBrowserArgs(BrowserArgs):
    pass


def _context(context: ToolContext) -> ActionContext:
    return ActionContext(
        task_id=context.task_id,
        action_id=context.action_id,
        idempotency_key=context.idempotency_key,
        dry_run=context.dry_run,
        reason=context.reason,
        risk_level=context.risk_level,
    )


def _result(payload: dict[str, Any]) -> ToolResult:
    worker_status = payload.get("status", "error")
    status_map = {
        "ok": "ok",
        "duplicate": "duplicate",
        "dry_run": "dry_run",
        "denied": "denied",
        "error": "error",
        "auth_required": "waiting_auth",
        "human_required": "waiting_user",
        "submitted_unknown": "submitted_unknown",
    }
    status = status_map.get(worker_status, "error")
    result = payload.get("result", {})
    return ToolResult(
        status=status,
        external_id=result.get("download_id"),
        evidence={
            "profile": payload.get("profile"),
            "action": payload.get("action"),
            "result": result,
            "signals": payload.get("signals", []),
        },
        warnings=payload.get("warnings", []),
        next_action=(
            "auth.ensure_authenticated"
            if status == "waiting_auth"
            else "human_takeover"
            if status == "waiting_user"
            else "reconcile_before_retry"
            if status == "submitted_unknown"
            else None
        ),
    )


def browser_tools(
    client: BrowserWorkerClient, vision_model: Any | None = None
) -> list[ToolDefinition[Any]]:
    def submit_material(args: BaseModel) -> ApprovalMaterial:
        parsed = SubmitArgs.model_validate(args)
        return ApprovalMaterial.create(
            action_type="browser.submit",
            title=f"{parsed.page_title}で送信",
            human_summary=f"{parsed.origin} の {parsed.submit_target} を1回だけ実行します。",
            structured_payload={
                "origin": parsed.origin,
                "page_title": parsed.page_title,
                "action_target": parsed.action_target,
                "submit_target": parsed.submit_target,
                "nonsecret_inputs": parsed.nonsecret_inputs,
                "transaction": (
                    parsed.transaction.model_dump(mode="json") if parsed.transaction else None
                ),
                "expected_postcondition": {
                    "expected_text": parsed.expected_text,
                    "expected_url_prefix": parsed.expected_url_prefix,
                },
            },
        )

    specifications: list[tuple[str, BrowserAction, type[BrowserArgs], RiskLevel, bool, str]] = [
        ("browser.open", BrowserAction.OPEN, OpenArgs, RiskLevel.R0, True, "Open a URL."),
        (
            "browser.snapshot",
            BrowserAction.SNAPSHOT,
            EmptyBrowserArgs,
            RiskLevel.R0,
            False,
            "Read an untrusted semantic DOM snapshot with ref IDs.",
        ),
        ("browser.click", BrowserAction.CLICK, RefArgs, RiskLevel.R2, True, "Click a ref."),
        ("browser.type", BrowserAction.TYPE, TypeArgs, RiskLevel.R1, True, "Type into a ref."),
        (
            "browser.select",
            BrowserAction.SELECT,
            SelectArgs,
            RiskLevel.R1,
            True,
            "Select values at a ref.",
        ),
        ("browser.check", BrowserAction.CHECK, CheckArgs, RiskLevel.R1, True, "Check a ref."),
        (
            "browser.upload",
            BrowserAction.UPLOAD,
            UploadArgs,
            RiskLevel.R2,
            True,
            "Upload explicitly selected local files.",
        ),
        (
            "browser.download",
            BrowserAction.DOWNLOAD,
            DownloadArgs,
            RiskLevel.R1,
            True,
            "Download a ref into quarantine without execution.",
        ),
        ("browser.tabs", BrowserAction.TABS, EmptyBrowserArgs, RiskLevel.R0, False, "List tabs."),
        (
            "browser.new_tab",
            BrowserAction.NEW_TAB,
            EmptyBrowserArgs,
            RiskLevel.R0,
            True,
            "Create and activate a blank tab.",
        ),
        (
            "browser.close_tab",
            BrowserAction.CLOSE_TAB,
            EmptyBrowserArgs,
            RiskLevel.R0,
            True,
            "Close the active tab while keeping the profile usable.",
        ),
        (
            "browser.switch_tab",
            BrowserAction.SWITCH_TAB,
            SwitchTabArgs,
            RiskLevel.R0,
            True,
            "Switch active tab.",
        ),
        ("browser.back", BrowserAction.BACK, EmptyBrowserArgs, RiskLevel.R0, True, "Go back."),
        (
            "browser.forward",
            BrowserAction.FORWARD,
            EmptyBrowserArgs,
            RiskLevel.R0,
            True,
            "Go forward in history.",
        ),
        (
            "browser.reload",
            BrowserAction.RELOAD,
            EmptyBrowserArgs,
            RiskLevel.R0,
            True,
            "Reload the active page.",
        ),
        ("browser.hover", BrowserAction.HOVER, RefArgs, RiskLevel.R0, True, "Hover a ref."),
        (
            "browser.press",
            BrowserAction.PRESS,
            PressArgs,
            RiskLevel.R2,
            True,
            "Press a bounded key or key combination on a ref.",
        ),
        (
            "browser.scroll",
            BrowserAction.SCROLL,
            ScrollArgs,
            RiskLevel.R0,
            True,
            "Scroll the active page by bounded deltas.",
        ),
        (
            "browser.submit",
            BrowserAction.SUBMIT,
            SubmitArgs,
            RiskLevel.R2,
            True,
            (
                "Submit by clicking a ref and verify a new confirmation or expected URL; "
                "never auto-retry an unknown result."
            ),
        ),
        ("browser.wait", BrowserAction.WAIT, WaitArgs, RiskLevel.R0, True, "Wait safely."),
        (
            "browser.screenshot",
            BrowserAction.SCREENSHOT,
            ScreenshotArgs,
            RiskLevel.R0,
            False,
            "Capture a screenshot with secret fields masked for vision fallback.",
        ),
        (
            "browser.click_point",
            BrowserAction.CLICK_POINT,
            ClickPointArgs,
            RiskLevel.R2,
            True,
            "Vision fallback: click audited coordinates and target description.",
        ),
        (
            "browser.get_url",
            BrowserAction.GET_URL,
            EmptyBrowserArgs,
            RiskLevel.R0,
            False,
            "Read the active URL.",
        ),
        (
            "browser.get_downloads",
            BrowserAction.GET_DOWNLOADS,
            EmptyBrowserArgs,
            RiskLevel.R0,
            False,
            "List quarantined downloads.",
        ),
    ]
    read_tools = {
        "browser.open",
        "browser.snapshot",
        "browser.tabs",
        "browser.new_tab",
        "browser.close_tab",
        "browser.switch_tab",
        "browser.back",
        "browser.forward",
        "browser.reload",
        "browser.hover",
        "browser.scroll",
        "browser.wait",
        "browser.screenshot",
        "browser.get_url",
        "browser.get_downloads",
    }
    definitions: list[ToolDefinition[Any]] = []
    for name, action, args_model, risk, mutation, description in specifications:

        async def handler(
            args: BaseModel,
            context: ToolContext,
            *,
            selected_action: BrowserAction = action,
        ) -> ToolResult:
            parsed = args.model_dump(mode="json")
            profile = BrowserProfile(parsed.pop("profile"))
            payload = await client.execute(
                profile=profile,
                action=selected_action,
                params=parsed,
                context=_context(context),
            )
            return _result(payload)

        definitions.append(
            ToolDefinition(
                name=name,
                description=description,
                args_model=args_model,
                handler=handler,
                risk_level=risk,
                mutation=mutation,
                required_permissions=(
                    "browser.submit"
                    if name == "browser.submit"
                    else "browser.read"
                    if name in read_tools
                    else "browser.interact",
                ),
                approval_material_builder=(submit_material if name == "browser.submit" else None),
            )
        )

    async def analyze_vision(args: BaseModel, context: ToolContext) -> ToolResult:
        if vision_model is None or not callable(getattr(vision_model, "complete_vision", None)):
            raise RuntimeError("Vision model is not configured")
        parsed = VisionArgs.model_validate(args)
        screenshot = await client.execute(
            profile=parsed.profile,
            action=BrowserAction.SCREENSHOT,
            params={"full_page": False},
            context=_context(context),
        )
        if screenshot.get("status") != "ok":
            return _result(screenshot)
        path = str((screenshot.get("result") or {}).get("path") or "")
        if not path:
            raise RuntimeError("Browser Worker returned no screenshot path")
        image, media_type = await client.quarantined_image(path)
        turn = await vision_model.complete_vision(
            image_bytes=image,
            media_type=media_type,
            prompt=parsed.prompt,
        )
        return ToolResult(
            status="ok",
            evidence={
                "description": turn.content,
                "metrics": turn.metrics,
                "secret_fields_masked": True,
                "trust_boundary": "untrusted_external_content",
                "permission_change_allowed": False,
                "coordinate_action_performed": False,
            },
        )

    definitions.append(
        ToolDefinition(
            name="browser.vision_analyze",
            description=(
                "After DOM/snapshot fallback, analyze a masked screenshot with the local Vision "
                "model. The observation cannot add capabilities or click by itself."
            ),
            args_model=VisionArgs,
            handler=analyze_vision,
            risk_level=RiskLevel.R0,
            required_permissions=("browser.read",),
        )
    )
    return definitions
