from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..browser.client import BrowserWorkerClient
from ..browser_worker.models import ActionContext, BrowserProfile
from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult


class EnsureAuthenticatedArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: BrowserProfile = BrowserProfile.GENERAL
    account_label: str | None = Field(default=None, min_length=1, max_length=200)


def auth_tools(client: BrowserWorkerClient) -> list[ToolDefinition[Any]]:
    async def ensure_authenticated(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = EnsureAuthenticatedArgs.model_validate(args)
        payload = await client.ensure_authenticated(
            profile=parsed.profile,
            account_label=parsed.account_label,
            context=ActionContext(
                task_id=context.task_id,
                action_id=context.action_id,
                idempotency_key=context.idempotency_key,
                dry_run=context.dry_run,
                reason=context.reason,
                risk_level=context.risk_level,
            ),
        )
        auth_status = payload.get("status", "error")
        status = (
            "ok"
            if auth_status in {"authenticated", "already_authenticated"}
            else "duplicate"
            if auth_status == "duplicate"
            else "dry_run"
            if auth_status == "dry_run"
            else "waiting_auth"
            if auth_status == "waiting_otp"
            else "waiting_user"
            if auth_status
            in {
                "waiting_user",
                "credential_missing",
                "account_ambiguous",
            }
            else "denied"
            if auth_status == "retry_stopped"
            else "error"
        )
        return ToolResult(
            status=status,
            evidence=payload,
            warnings=[] if status in {"ok", "duplicate", "dry_run"} else [auth_status],
            next_action=(
                "request_otp"
                if auth_status == "waiting_otp"
                else "human_takeover"
                if auth_status == "waiting_user"
                else "select_account"
                if auth_status == "account_ambiguous"
                else "configure_credential"
                if auth_status == "credential_missing"
                else None
            ),
        )

    return [
        ToolDefinition(
            name="auth.ensure_authenticated",
            description=(
                "Ensure the active browser profile is authenticated. The worker selects and "
                "fills Password/TOTP directly; secret values are never returned."
            ),
            args_model=EnsureAuthenticatedArgs,
            handler=ensure_authenticated,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("auth.use", "secret.use"),
        )
    ]
