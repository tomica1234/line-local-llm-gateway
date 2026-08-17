from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import uuid4

from ..browser_worker.controller import HumanTakeoverActive
from ..browser_worker.models import (
    ActionContext,
    BrowserAction,
    BrowserProfile,
    EmptyParams,
    RefParams,
    WaitParams,
)
from ..browser_worker.store import BrowserWorkerStore
from ..secret.models import SecretAction, SecretKind, SecretMetadata
from ..secret.store import SecretStore, normalize_origin
from .models import AuthResult


class AuthBrowserController(Protocol):
    async def current_url(self, profile: BrowserProfile) -> str: ...

    async def execute(
        self,
        profile: BrowserProfile,
        action: BrowserAction,
        params: Any,
        context: ActionContext | None,
    ) -> dict[str, Any]: ...

    async def fill_secret(
        self,
        profile: BrowserProfile,
        *,
        ref: str,
        value: str,
        action: SecretAction,
    ) -> dict[str, Any]: ...

    async def start_takeover(
        self,
        profile: BrowserProfile,
        *,
        reason: str,
        context: ActionContext,
        timeout_seconds: int,
    ) -> dict[str, Any]: ...


_OTP = re.compile(r"otp|totp|one.?time|verification.?code|認証コード|確認コード", re.I)
_USERNAME = re.compile(r"username|user.?id|login|account|e.?mail|ユーザー|メール|アカウント", re.I)
_SUBMIT = re.compile(r"log.?in|sign.?in|continue|next|verify|submit|ログイン|次へ|確認", re.I)
_ERROR = re.compile(r"incorrect|invalid|failed|try again|誤り|正しくありません|失敗", re.I)


class AuthOrchestrator:
    def __init__(
        self,
        controller: AuthBrowserController,
        secrets: SecretStore,
        store: BrowserWorkerStore,
        *,
        max_attempts: int = 3,
        otp_ttl_seconds: int = 300,
    ) -> None:
        self.controller = controller
        self.secrets = secrets
        self.store = store
        self.max_attempts = max_attempts
        self.otp_ttl_seconds = otp_ttl_seconds

    async def ensure(
        self,
        profile: BrowserProfile,
        *,
        account_label: str | None,
        context: ActionContext,
    ) -> AuthResult:
        page_url = await self.controller.current_url(profile)
        try:
            origin = normalize_origin(page_url)
        except ValueError:
            return AuthResult(
                status="error",
                profile=profile,
                reason_code="AUTH_ORIGIN_INVALID",
            )
        observation = await self._snapshot(profile)
        signals = observation.get("signals", [])
        human_signal = next(
            (item for item in signals if item.get("type") == "human_required"), None
        )
        if human_signal:
            await self._ensure_takeover(
                profile, human_signal.get("reason", "auth_human_factor"), context
            )
            return AuthResult(
                status="waiting_user",
                profile=profile,
                origin=origin,
                account_label=account_label,
                reason_code=f"HUMAN_{human_signal.get('reason', 'REQUIRED').upper()}",
                signals=signals,
            )
        nodes = observation.get("result", {}).get("nodes", [])
        username_node = self._username_node(nodes)
        password_node = next((item for item in nodes if item.get("type") == "password"), None)
        otp_node = self._otp_node(nodes)
        if (
            username_node is None
            and password_node is None
            and otp_node is None
            and not any(item.get("type") == "auth_required" for item in signals)
        ):
            return AuthResult(
                status="already_authenticated",
                profile=profile,
                origin=origin,
                account_label=account_label,
                reason_code="EXISTING_SESSION_VALID",
            )

        if username_node is not None:
            username = self._credential(
                origin=origin,
                action=SecretAction.USERNAME_FILL,
                kind=SecretKind.USERNAME,
                account_label=account_label,
            )
            if isinstance(username, AuthResult):
                return username.model_copy(update={"profile": profile, "origin": origin})
            await self._direct_fill(
                profile=profile,
                ref=username_node["ref"],
                credential=username,
                action=SecretAction.USERNAME_FILL,
                origin=origin,
                context=context,
            )
            if password_node is None:
                await self._click_submit(profile, nodes, context)
                observation = await self._settle_and_snapshot(profile, context)
                nodes = observation.get("result", {}).get("nodes", [])
                signals = observation.get("signals", [])
                password_node = next(
                    (item for item in nodes if item.get("type") == "password"), None
                )
                otp_node = self._otp_node(nodes)

        if password_node is not None:
            password = self._credential(
                origin=origin,
                action=SecretAction.PASSWORD_FILL,
                kind=SecretKind.PASSWORD,
                account_label=account_label,
            )
            if isinstance(password, AuthResult):
                return password.model_copy(update={"profile": profile, "origin": origin})
            await self._direct_fill(
                profile=profile,
                ref=password_node["ref"],
                credential=password,
                action=SecretAction.PASSWORD_FILL,
                origin=origin,
                context=context,
            )
            await self._click_submit(profile, nodes, context)
            observation = await self._settle_and_snapshot(profile, context)
            nodes = observation.get("result", {}).get("nodes", [])
            signals = observation.get("signals", [])
            otp_node = self._otp_node(nodes)

        human_signal = next(
            (item for item in signals if item.get("type") == "human_required"), None
        )
        if human_signal:
            await self._ensure_takeover(
                profile, human_signal.get("reason", "auth_human_factor"), context
            )
            return AuthResult(
                status="waiting_user",
                profile=profile,
                origin=origin,
                account_label=account_label,
                reason_code="HUMAN_FACTOR_REQUIRED",
                signals=signals,
            )

        if otp_node is not None:
            totp = self._credential(
                origin=origin,
                action=SecretAction.TOTP_FILL,
                kind=SecretKind.TOTP_SEED,
                account_label=account_label,
            )
            if isinstance(totp, SecretMetadata):
                await self._direct_fill(
                    profile=profile,
                    ref=otp_node["ref"],
                    credential=totp,
                    action=SecretAction.TOTP_FILL,
                    origin=origin,
                    context=context,
                )
                await self._click_submit(profile, nodes, context)
                final = await self._settle_and_snapshot(profile, context)
                if self._auth_fields(final):
                    return self._failure_result(
                        profile=profile,
                        origin=origin,
                        account_label=account_label,
                        context=context,
                        factor="totp",
                    )
                return AuthResult(
                    status="authenticated",
                    profile=profile,
                    origin=origin,
                    account_label=totp.account_label,
                    factor="totp",
                    reason_code="TOTP_AUTHENTICATED",
                )
            if totp.status == "account_ambiguous":
                return totp.model_copy(update={"profile": profile, "origin": origin})
            return self._waiting_otp(
                profile=profile,
                origin=origin,
                account_label=account_label,
                field_ref=otp_node["ref"],
                context=context,
            )

        if self._auth_fields(observation):
            return self._failure_result(
                profile=profile,
                origin=origin,
                account_label=account_label,
                context=context,
                factor="password",
            )
        return AuthResult(
            status="authenticated",
            profile=profile,
            origin=origin,
            account_label=account_label,
            factor="password",
            reason_code="PASSWORD_AUTHENTICATED",
        )

    async def submit_otp(
        self, profile: BrowserProfile, *, auth_session_id: str, code: str
    ) -> AuthResult:
        session = self.store.get_auth_session(auth_session_id)
        if session["profile"] != profile.value:
            raise PermissionError("Auth session profile mismatch")
        if session["state"] != "WAITING_OTP":
            raise ValueError("Auth session is not waiting for an OTP")
        expired = not session["expires_at"] or (
            datetime.fromisoformat(session["expires_at"]) <= datetime.now(UTC)
        )
        if expired:
            session["state"] = "EXPIRED"
            self.store.put_auth_session(session)
            raise PermissionError("OTP session expired")
        current_origin = normalize_origin(await self.controller.current_url(profile))
        if current_origin != session["origin"]:
            raise PermissionError("OTP origin binding failed")
        if session["attempts"] >= session["max_attempts"]:
            raise PermissionError("OTP retry limit reached")
        context = ActionContext(
            task_id=session["task_id"],
            action_id=f"otp-{uuid4()}",
            idempotency_key=f"{auth_session_id}:otp:{session['attempts'] + 1}",
            reason="ユーザーが認証Taskへ直接提供した短時間OTPを入力するため",
        )
        session["attempts"] += 1
        try:
            await self.controller.fill_secret(
                profile,
                ref=session["field_ref"],
                value=code,
                action=SecretAction.TOTP_FILL,
            )
            observation = await self._snapshot(profile)
            await self._click_submit(
                profile, observation.get("result", {}).get("nodes", []), context
            )
            final = await self._settle_and_snapshot(profile, context)
        finally:
            code = ""
        if self._auth_fields(final):
            session["state"] = (
                "RETRY_STOPPED" if session["attempts"] >= session["max_attempts"] else "WAITING_OTP"
            )
            self.store.put_auth_session(session)
            return AuthResult(
                status=("retry_stopped" if session["state"] == "RETRY_STOPPED" else "waiting_otp"),
                profile=profile,
                origin=current_origin,
                account_label=session["account_label"],
                auth_session_id=auth_session_id,
                factor=session["factor"],
                reason_code=(
                    "AUTH_RETRY_LIMIT_REACHED"
                    if session["state"] == "RETRY_STOPPED"
                    else "OTP_INVALID_OR_UNVERIFIED"
                ),
            )
        session["state"] = "AUTHENTICATED"
        self.store.put_auth_session(session)
        return AuthResult(
            status="authenticated",
            profile=profile,
            origin=current_origin,
            account_label=session["account_label"],
            auth_session_id=auth_session_id,
            factor=session["factor"],
            reason_code="OTP_AUTHENTICATED",
        )

    def _credential(
        self,
        *,
        origin: str,
        action: SecretAction,
        kind: SecretKind,
        account_label: str | None,
    ) -> SecretMetadata | AuthResult:
        candidates = [
            item
            for item in self.secrets.list_metadata()
            if item.enabled
            and item.kind is kind
            and origin in item.allowed_origins
            and action in item.allowed_actions
            and (account_label is None or item.account_label == account_label)
        ]
        if not candidates:
            return AuthResult(
                status="credential_missing",
                profile=BrowserProfile.GENERAL,
                account_label=account_label,
                reason_code="NO_MATCHING_CREDENTIAL",
            )
        if len(candidates) > 1:
            return AuthResult(
                status="account_ambiguous",
                profile=BrowserProfile.GENERAL,
                account_label=account_label,
                reason_code="MULTIPLE_MATCHING_ACCOUNTS",
            )
        return candidates[0]

    async def _direct_fill(
        self,
        *,
        profile: BrowserProfile,
        ref: str,
        credential: SecretMetadata,
        action: SecretAction,
        origin: str,
        context: ActionContext,
    ) -> None:
        try:
            value = self.secrets.value_for_use(
                credential_id=credential.credential_id,
                origin=origin,
                action=action,
                task_id=context.task_id,
            )
            await self.controller.fill_secret(profile, ref=ref, value=value, action=action)
            del value
        except Exception:
            self.secrets.record_use(
                credential_id=credential.credential_id,
                task_id=context.task_id,
                origin=origin,
                action=action,
                result="error",
            )
            raise
        self.secrets.record_use(
            credential_id=credential.credential_id,
            task_id=context.task_id,
            origin=origin,
            action=action,
            result="ok",
        )

    async def _snapshot(self, profile: BrowserProfile) -> dict[str, Any]:
        return await self.controller.execute(profile, BrowserAction.SNAPSHOT, EmptyParams(), None)

    async def _ensure_takeover(
        self, profile: BrowserProfile, reason: str, context: ActionContext
    ) -> None:
        try:
            await self.controller.start_takeover(
                profile,
                reason=reason,
                context=context,
                timeout_seconds=300,
            )
        except HumanTakeoverActive:
            pass

    async def _settle_and_snapshot(
        self, profile: BrowserProfile, context: ActionContext
    ) -> dict[str, Any]:
        await self.controller.execute(
            profile, BrowserAction.WAIT, WaitParams(timeout_ms=800), context
        )
        return await self._snapshot(profile)

    async def _click_submit(
        self, profile: BrowserProfile, nodes: list[dict[str, Any]], context: ActionContext
    ) -> bool:
        submit = next(
            (
                item
                for item in nodes
                if item.get("role") == "button" and _SUBMIT.search(item.get("name") or "")
            ),
            None,
        )
        if submit is None:
            return False
        await self.controller.execute(
            profile, BrowserAction.CLICK, RefParams(ref=submit["ref"]), context
        )
        return True

    def _waiting_otp(
        self,
        *,
        profile: BrowserProfile,
        origin: str,
        account_label: str | None,
        field_ref: str,
        context: ActionContext,
    ) -> AuthResult:
        auth_session_id = str(uuid4())
        now = datetime.now(UTC)
        self.store.put_auth_session(
            {
                "auth_session_id": auth_session_id,
                "profile": profile.value,
                "task_id": context.task_id,
                "origin": origin,
                "account_label": account_label,
                "factor": "email_or_sms_otp",
                "field_ref": field_ref,
                "state": "WAITING_OTP",
                "attempts": 0,
                "max_attempts": self.max_attempts,
                "expires_at": (now + timedelta(seconds=self.otp_ttl_seconds)).isoformat(),
                "created_at": now.isoformat(),
            }
        )
        return AuthResult(
            status="waiting_otp",
            profile=profile,
            origin=origin,
            account_label=account_label,
            auth_session_id=auth_session_id,
            factor="email_or_sms_otp",
            reason_code="OTP_REQUIRED",
        )

    def _failure_result(
        self,
        *,
        profile: BrowserProfile,
        origin: str,
        account_label: str | None,
        context: ActionContext,
        factor: str,
    ) -> AuthResult:
        auth_session_id = str(uuid4())
        now = datetime.now(UTC)
        self.store.put_auth_session(
            {
                "auth_session_id": auth_session_id,
                "profile": profile.value,
                "task_id": context.task_id,
                "origin": origin,
                "account_label": account_label,
                "factor": factor,
                "state": "RETRY_STOPPED",
                "attempts": 1,
                "max_attempts": self.max_attempts,
                "created_at": now.isoformat(),
            }
        )
        return AuthResult(
            status="retry_stopped",
            profile=profile,
            origin=origin,
            account_label=account_label,
            auth_session_id=auth_session_id,
            factor=factor,
            reason_code="AUTH_SUCCESS_NOT_VERIFIED",
        )

    @staticmethod
    def _username_node(nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in nodes
                if item.get("role") == "textbox"
                and item.get("type") != "password"
                and not item.get("value")
                and _USERNAME.search(
                    " ".join(str(item.get(key) or "") for key in ("name", "type", "autocomplete"))
                )
            ),
            None,
        )

    @staticmethod
    def _otp_node(nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in nodes
                if item.get("role") == "textbox"
                and item.get("type") != "password"
                and _OTP.search(" ".join(str(item.get(key) or "") for key in ("name", "type")))
            ),
            None,
        )

    @staticmethod
    def _auth_fields(observation: dict[str, Any]) -> bool:
        nodes = observation.get("result", {}).get("nodes", [])
        return (
            bool(AuthOrchestrator._username_node(nodes))
            or any(item.get("type") == "password" for item in nodes)
            or bool(AuthOrchestrator._otp_node(nodes))
            or any(
                _ERROR.search(item.get("name") or "")
                for item in nodes
                if item.get("role") == "alert"
            )
        )
