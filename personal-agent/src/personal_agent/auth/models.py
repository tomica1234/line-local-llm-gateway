from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from ..browser_worker.models import ActionContext, BrowserProfile


class AuthEnsureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_label: str | None = Field(default=None, min_length=1, max_length=200)
    context: ActionContext


class AuthOtpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth_session_id: str = Field(min_length=8, max_length=128)
    code: SecretStr


class AuthResult(BaseModel):
    status: Literal[
        "authenticated",
        "already_authenticated",
        "waiting_otp",
        "waiting_user",
        "credential_missing",
        "account_ambiguous",
        "retry_stopped",
        "error",
        "duplicate",
        "dry_run",
    ]
    profile: BrowserProfile
    origin: str | None = None
    account_label: str | None = None
    auth_session_id: str | None = None
    factor: str | None = None
    reason_code: str
    signals: list[dict[str, str]] = Field(default_factory=list)
