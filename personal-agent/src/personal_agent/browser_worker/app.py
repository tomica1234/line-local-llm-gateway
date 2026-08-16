from __future__ import annotations

import asyncio
import platform
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from typing import Annotated, Any, Protocol

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from ..auth.models import AuthEnsureRequest, AuthOtpRequest
from ..auth.service import AuthOrchestrator
from ..secret.models import SecretCreate, SecretPutRequest
from ..secret.protection import protector_from_environment
from ..secret.store import SecretStore, normalize_origin
from .config import BrowserWorkerSettings
from .connectors import (
    ConnectorProvider,
    ConnectorSearchRequest,
    ConnectorSendRequest,
    ConnectorWorkerService,
)
from .controller import (
    BrowserUnavailable,
    HumanTakeoverActive,
    PlaywrightController,
    SecretInputRequired,
)
from .models import (
    ACTION_PARAMETER_MODELS,
    MUTATION_ACTIONS,
    ActionContext,
    BrowserAction,
    BrowserActionRequest,
    BrowserProfile,
    BrowserResult,
    SecretFillRequest,
    TakeoverReleaseRequest,
    TakeoverStartRequest,
)
from .security import validate_navigation_url
from .store import BrowserWorkerStore


class BrowserController(Protocol):
    async def execute(
        self,
        profile: BrowserProfile,
        action: BrowserAction,
        params: BaseModel,
        context: ActionContext | None,
    ) -> dict[str, Any]: ...

    async def list_profiles(self) -> list[dict[str, Any]]: ...

    async def current_url(self, profile: BrowserProfile) -> str: ...

    async def close_profile(self, profile: BrowserProfile) -> None: ...

    async def start_takeover(
        self,
        profile: BrowserProfile,
        *,
        reason: str,
        context: ActionContext,
        timeout_seconds: int,
    ) -> dict[str, Any]: ...

    async def release_takeover(
        self, profile: BrowserProfile, *, outcome: str
    ) -> dict[str, Any]: ...

    async def takeover_status(self, profile: BrowserProfile) -> dict[str, Any]: ...

    async def fill_secret(
        self,
        profile: BrowserProfile,
        *,
        ref: str,
        value: str,
        action: Any,
    ) -> dict[str, Any]: ...

    async def reap_timeouts(self) -> list[str]: ...

    async def close(self) -> None: ...


def create_browser_worker_app(
    settings: BrowserWorkerSettings | None = None,
    controller: BrowserController | None = None,
    secret_store: SecretStore | None = None,
    secret_lock_checker: Callable[[BrowserProfile], Awaitable[tuple[bool, str]]] | None = None,
    browser_lock_checker: Callable[[BrowserProfile], Awaitable[tuple[bool, str]]] | None = None,
    connector_service: ConnectorWorkerService | None = None,
) -> FastAPI:
    configured = settings or BrowserWorkerSettings.from_env()
    store = BrowserWorkerStore(configured.state_db_path)
    store.initialize()
    runtime_controller = controller or PlaywrightController(configured, store)
    runtime_secret_store = secret_store

    def secrets_runtime() -> SecretStore:
        nonlocal runtime_secret_store
        if runtime_secret_store is None:
            runtime_secret_store = SecretStore(
                configured.secret_db_path, protector_from_environment()
            )
            runtime_secret_store.initialize()
        return runtime_secret_store

    def auth_runtime() -> AuthOrchestrator:
        return AuthOrchestrator(runtime_controller, secrets_runtime(), store)

    def connectors_runtime() -> ConnectorWorkerService:
        return connector_service or ConnectorWorkerService(secrets_runtime(), store)

    async def core_lock_check(
        profile: BrowserProfile, *, require_browser: bool, require_secret: bool
    ) -> tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{configured.core_base_url}/api/system/locks")
                response.raise_for_status()
                locks = response.json()
        except (httpx.HTTPError, ValueError, TypeError):
            return False, "CORE_LOCK_STATE_UNAVAILABLE"
        values = {
            key: value.get("value") if isinstance(value, dict) else value
            for key, value in locks.items()
        }
        if values.get("global_pause"):
            return False, "GLOBAL_PAUSE_ENABLED"
        if require_browser and values.get("browser_lock"):
            return False, "BROWSER_LOCK_ENABLED"
        if require_secret and values.get("secret_lock"):
            return False, "SECRET_LOCK_ENABLED"
        if profile is BrowserProfile.FINANCE and values.get("finance_lock"):
            return False, "FINANCE_LOCK_ENABLED"
        return True, "LOCKS_CLEAR"

    async def core_secret_lock_check(profile: BrowserProfile) -> tuple[bool, str]:
        return await core_lock_check(profile, require_browser=True, require_secret=True)

    async def core_connector_lock_check(profile: BrowserProfile) -> tuple[bool, str]:
        return await core_lock_check(profile, require_browser=False, require_secret=True)

    async def core_browser_lock_check(profile: BrowserProfile) -> tuple[bool, str]:
        return await core_lock_check(profile, require_browser=True, require_secret=False)

    check_secret_locks = secret_lock_checker or core_secret_lock_check
    check_connector_locks = secret_lock_checker or core_connector_lock_check
    check_browser_locks = browser_lock_checker or core_browser_lock_check

    async def timeout_loop() -> None:
        while True:
            await asyncio.sleep(5)
            task_ids = await runtime_controller.reap_timeouts()
            if task_ids and configured.core_base_url:
                async with httpx.AsyncClient(timeout=10) as client:
                    for task_id in task_ids:
                        try:
                            await client.post(
                                f"{configured.core_base_url}/api/tasks/{task_id}/pause"
                            )
                        except httpx.HTTPError:
                            # The Worker remains locked/paused even if Core is temporarily offline.
                            pass

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        timeout_task = asyncio.create_task(timeout_loop())
        try:
            yield
        finally:
            timeout_task.cancel()
            with suppress(asyncio.CancelledError):
                await timeout_task
            await runtime_controller.close()

    app = FastAPI(
        title="Local Personal Agent Browser Worker",
        version="0.1.0",
        description="Authenticated typed Playwright primitives for a local Windows host.",
        lifespan=lifespan,
    )
    app.state.settings = configured
    app.state.store = store
    app.state.controller = runtime_controller

    def require_worker_token(
        request: Request,
        x_browser_worker_token: Annotated[str | None, Header()] = None,
    ) -> None:
        client_host = request.client.host if request.client else ""
        if not configured.client_allowed(client_host):
            raise HTTPException(status_code=403, detail="Browser Worker client is not allowed")
        if not configured.token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        if not x_browser_worker_token or not secrets.compare_digest(
            x_browser_worker_token, configured.token
        ):
            raise HTTPException(status_code=401, detail="Invalid Browser Worker token")

    protected = [Depends(require_worker_token)]

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.get("/v1/health", dependencies=protected)
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "platform": platform.system(),
            "windows": platform.system() == "Windows",
            "headed": not configured.headless,
            "browser_channel": configured.browser_channel or "chromium",
            "token_configured": bool(configured.token),
        }

    @app.get("/v1/profiles", dependencies=protected)
    async def profiles() -> list[dict[str, Any]]:
        return await runtime_controller.list_profiles()

    @app.post("/v1/connectors/{provider}/send", dependencies=protected)
    async def connector_send(
        provider: ConnectorProvider, request: ConnectorSendRequest
    ) -> dict[str, Any]:
        allowed, reason = await check_connector_locks(BrowserProfile.COMMUNICATION)
        if not allowed:
            raise HTTPException(status_code=423, detail=reason)
        return await connectors_runtime().send(provider, request)

    @app.post("/v1/connectors/{provider}/search", dependencies=protected)
    async def connector_search(
        provider: ConnectorProvider, request: ConnectorSearchRequest
    ) -> dict[str, Any]:
        allowed, reason = await check_connector_locks(BrowserProfile.COMMUNICATION)
        if not allowed:
            raise HTTPException(status_code=423, detail=reason)
        return await connectors_runtime().search(provider, request)

    @app.delete("/v1/profiles/{profile}", dependencies=protected)
    async def close_profile(profile: BrowserProfile) -> dict[str, str]:
        await runtime_controller.close_profile(profile)
        store.record_audit(
            profile=profile,
            task_id=None,
            actor="agent_core",
            action="browser.profile.close",
            result="ok",
        )
        return {"status": "closed", "profile": profile.value}

    @app.post(
        "/v1/browser/{profile}/{action}",
        response_model=BrowserResult,
        dependencies=protected,
    )
    async def browser_action(
        profile: BrowserProfile,
        action: BrowserAction,
        request: BrowserActionRequest,
    ) -> BrowserResult:
        if action in MUTATION_ACTIONS and request.context is None:
            raise HTTPException(
                status_code=422,
                detail="Mutation browser actions require an action context",
            )
        allowed, reason = await check_browser_locks(profile)
        if not allowed:
            raise HTTPException(status_code=423, detail=reason)
        try:
            params = ACTION_PARAMETER_MODELS[action].model_validate(request.params)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc
        if action is BrowserAction.OPEN:
            validate_navigation_url(
                params.model_dump()["url"],
                profile=profile,
                finance_allowlist=configured.finance_allowlist,
                allow_private_navigation=configured.allow_private_navigation,
            )
        if action is BrowserAction.DOWNLOAD and profile is BrowserProfile.FINANCE:
            raise HTTPException(status_code=403, detail="Finance profile downloads are disabled")

        claim: tuple[str, dict[str, Any] | None] | None = None
        if action in MUTATION_ACTIONS:
            context = request.context
            assert context is not None
            claim = store.begin_action(
                profile=profile,
                idempotency_key=context.idempotency_key,
                task_id=context.task_id,
                action_id=context.action_id,
                action=f"browser.{action.value}",
            )
            disposition, previous = claim
            if disposition == "duplicate":
                duplicate = BrowserResult.model_validate(previous)
                if duplicate.status == "submitted_unknown":
                    duplicate.warnings.append("IDEMPOTENT_REPLAY_SUPPRESSED_PENDING_RECONCILIATION")
                    return duplicate
                return duplicate.model_copy(update={"status": "duplicate"})
            if disposition == "in_progress":
                return BrowserResult(
                    status="submitted_unknown",
                    profile=profile,
                    action=action.value,
                    warnings=["A previous mutation with this idempotency key is unresolved"],
                )
            if context.dry_run:
                response = BrowserResult(
                    status="dry_run",
                    profile=profile,
                    action=action.value,
                    result={"validated": True, "executed": False},
                )
                store.finish_action(
                    profile=profile,
                    idempotency_key=context.idempotency_key,
                    result=response.model_dump(mode="json"),
                )
                return response

        try:
            payload = await runtime_controller.execute(profile, action, params, request.context)
            signals = payload.get("signals", [])
            response_status = "ok"
            if any(item.get("type") == "human_required" for item in signals):
                response_status = "human_required"
            elif any(item.get("type") == "auth_required" for item in signals):
                response_status = "auth_required"
            elif action is BrowserAction.SUBMIT and not payload.get("result", {}).get("verified"):
                response_status = "submitted_unknown"
            response = BrowserResult(
                status=response_status,
                profile=profile,
                action=action.value,
                result=payload.get("result", {}),
                signals=signals,
            )
        except SecretInputRequired as exc:
            response = BrowserResult(
                status="denied",
                profile=profile,
                action=action.value,
                warnings=[str(exc)],
            )
        except HumanTakeoverActive as exc:
            response = BrowserResult(
                status="human_required",
                profile=profile,
                action=action.value,
                warnings=[str(exc)],
            )
        except BrowserUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            response = BrowserResult(
                status="submitted_unknown" if action in MUTATION_ACTIONS else "error",
                profile=profile,
                action=action.value,
                warnings=[type(exc).__name__],
                result={"verified": False},
            )

        if action in MUTATION_ACTIONS and request.context is not None:
            store.finish_action(
                profile=profile,
                idempotency_key=request.context.idempotency_key,
                result=response.model_dump(mode="json"),
            )
        store.record_audit(
            profile=profile,
            task_id=request.context.task_id if request.context else None,
            actor="agent_core",
            action=f"browser.{action.value}",
            result=response.status,
            details={
                "action_id": request.context.action_id if request.context else None,
                "reason": request.context.reason if request.context else None,
                "coordinates_recorded": action is BrowserAction.CLICK_POINT,
                "input_values_recorded": False,
            },
        )
        return response

    @app.post("/v1/takeover/{profile}/start", dependencies=protected)
    async def takeover_start(
        profile: BrowserProfile, request: TakeoverStartRequest
    ) -> dict[str, Any]:
        timeout = request.timeout_seconds or configured.takeover_timeout_seconds
        disposition, previous = store.begin_action(
            profile=profile,
            idempotency_key=request.context.idempotency_key,
            task_id=request.context.task_id,
            action_id=request.context.action_id,
            action="human_takeover.start",
        )
        if disposition == "duplicate":
            return {**(previous or {}), "duplicate": True}
        if disposition == "in_progress":
            raise HTTPException(status_code=409, detail="Takeover start is already in progress")
        result = await runtime_controller.start_takeover(
            profile,
            reason=request.reason,
            context=request.context,
            timeout_seconds=timeout,
        )
        store.finish_action(
            profile=profile,
            idempotency_key=request.context.idempotency_key,
            result=result,
        )
        return result

    @app.get("/v1/takeover/{profile}", dependencies=protected)
    async def takeover_status(profile: BrowserProfile) -> dict[str, Any]:
        return await runtime_controller.takeover_status(profile)

    @app.post("/v1/takeover/{profile}/release", dependencies=protected)
    async def takeover_release(
        profile: BrowserProfile, request: TakeoverReleaseRequest
    ) -> dict[str, Any]:
        return await runtime_controller.release_takeover(profile, outcome=request.outcome)

    @app.get("/v1/audit", dependencies=protected)
    async def audit(limit: int = Query(default=200, ge=1, le=1_000)) -> list[dict[str, Any]]:
        return store.audit(limit=limit)

    @app.post("/v1/secret/{profile}/fill", dependencies=protected)
    async def fill_secret(profile: BrowserProfile, request: SecretFillRequest) -> dict[str, Any]:
        allowed, reason_code = await check_secret_locks(profile)
        if not allowed:
            raise HTTPException(status_code=423, detail=reason_code)
        disposition, previous = store.begin_action(
            profile=profile,
            idempotency_key=request.context.idempotency_key,
            task_id=request.context.task_id,
            action_id=request.context.action_id,
            action=f"secret.{request.action.value}",
        )
        if disposition == "duplicate":
            return {**(previous or {}), "status": "duplicate"}
        if disposition == "in_progress":
            raise HTTPException(status_code=409, detail="Secret fill is already in progress")
        if request.context.dry_run:
            result = {
                "status": "dry_run",
                "credential_id": request.credential_ref,
                "action": request.action.value,
                "filled": False,
            }
            store.finish_action(
                profile=profile,
                idempotency_key=request.context.idempotency_key,
                result=result,
            )
            return result
        secret_service = secrets_runtime()
        page_url = await runtime_controller.current_url(profile)
        try:
            origin = normalize_origin(page_url)
            value = secret_service.value_for_use(
                credential_id=request.credential_ref,
                origin=origin,
                action=request.action,
                task_id=request.context.task_id,
            )
            browser_result = await runtime_controller.fill_secret(
                profile,
                ref=request.ref,
                value=value,
                action=request.action,
            )
            del value
            secret_service.record_use(
                credential_id=request.credential_ref,
                task_id=request.context.task_id,
                origin=origin,
                action=request.action,
                result="ok",
            )
            result = {
                "status": "ok",
                "credential_id": request.credential_ref,
                "origin": origin,
                "action": request.action.value,
                "filled": bool(browser_result.get("filled")),
            }
        except Exception as exc:
            try:
                secret_service.record_use(
                    credential_id=request.credential_ref,
                    task_id=request.context.task_id,
                    origin=page_url,
                    action=request.action,
                    result=("denied" if isinstance(exc, (PermissionError, KeyError)) else "error"),
                )
            except ValueError:
                pass
            raise HTTPException(
                status_code=403 if isinstance(exc, (PermissionError, KeyError)) else 409,
                detail=f"Secret fill failed: {type(exc).__name__}",
            ) from exc
        store.finish_action(
            profile=profile,
            idempotency_key=request.context.idempotency_key,
            result=result,
        )
        store.record_audit(
            profile=profile,
            task_id=request.context.task_id,
            actor="secret_broker",
            action=f"secret.{request.action.value}",
            result="ok",
            details={
                "credential_id": request.credential_ref,
                "origin": result["origin"],
                "value_recorded": False,
            },
        )
        return result

    @app.get("/v1/secrets", dependencies=protected)
    async def secret_metadata() -> list[dict[str, Any]]:
        return [item.model_dump(mode="json") for item in secrets_runtime().list_metadata()]

    @app.post("/v1/secrets", dependencies=protected)
    async def put_secret(request: SecretPutRequest) -> dict[str, Any]:
        allowed, reason_code = await check_connector_locks(BrowserProfile.ADMINISTRATION)
        if not allowed:
            raise HTTPException(status_code=423, detail=reason_code)
        value = request.value.get_secret_value()
        try:
            create = SecretCreate.model_validate(request.model_dump(exclude={"value"}))
            metadata = secrets_runtime().put(create, value)
        finally:
            value = ""
        store.record_audit(
            profile=BrowserProfile.ADMINISTRATION,
            task_id=None,
            actor="primary_user",
            action="secret.put",
            result="ok",
            details={
                "credential_id": metadata.credential_id,
                "kind": metadata.kind.value,
                "origins": metadata.allowed_origins,
                "value_recorded": False,
            },
        )
        return metadata.model_dump(mode="json")

    @app.get("/v1/secrets/usage", dependencies=protected)
    async def secret_usage(
        limit: int = Query(default=200, ge=1, le=1_000),
    ) -> list[dict[str, str]]:
        return secrets_runtime().usage(limit=limit)

    @app.post("/v1/auth/{profile}/ensure", dependencies=protected)
    async def ensure_authenticated(
        profile: BrowserProfile, request: AuthEnsureRequest
    ) -> dict[str, Any]:
        allowed, reason_code = await check_secret_locks(profile)
        if not allowed:
            raise HTTPException(status_code=423, detail=reason_code)
        disposition, previous = store.begin_action(
            profile=profile,
            idempotency_key=request.context.idempotency_key,
            task_id=request.context.task_id,
            action_id=request.context.action_id,
            action="auth.ensure_authenticated",
        )
        if disposition == "duplicate":
            return {**(previous or {}), "status": "duplicate"}
        if disposition == "in_progress":
            raise HTTPException(status_code=409, detail="Authentication is already in progress")
        if request.context.dry_run:
            payload = {
                "status": "dry_run",
                "profile": profile.value,
                "reason_code": "AUTH_DRY_RUN_VALIDATED",
            }
        else:
            payload = (
                await auth_runtime().ensure(
                    profile,
                    account_label=request.account_label,
                    context=request.context,
                )
            ).model_dump(mode="json")
        store.finish_action(
            profile=profile,
            idempotency_key=request.context.idempotency_key,
            result=payload,
        )
        store.record_audit(
            profile=profile,
            task_id=request.context.task_id,
            actor="auth_orchestrator",
            action="auth.ensure_authenticated",
            result=payload["status"],
            details={
                "origin": payload.get("origin"),
                "account_label": payload.get("account_label"),
                "factor": payload.get("factor"),
                "secret_value_recorded": False,
                "otp_value_recorded": False,
            },
        )
        return payload

    @app.post("/v1/auth/{profile}/otp", dependencies=protected)
    async def submit_auth_otp(profile: BrowserProfile, request: AuthOtpRequest) -> dict[str, Any]:
        allowed, reason_code = await check_secret_locks(profile)
        if not allowed:
            raise HTTPException(status_code=423, detail=reason_code)
        code = request.code.get_secret_value()
        try:
            session = store.get_auth_session(request.auth_session_id)
            payload = (
                await auth_runtime().submit_otp(
                    profile,
                    auth_session_id=request.auth_session_id,
                    code=code,
                )
            ).model_dump(mode="json")
            payload["task_id"] = session["task_id"]
        finally:
            code = ""
        store.record_audit(
            profile=profile,
            task_id=(session.get("task_id") if request.auth_session_id else None),
            actor="primary_user",
            action="auth.otp.submit",
            result=payload["status"],
            details={
                "auth_session_id": request.auth_session_id,
                "otp_value_recorded": False,
            },
        )
        return payload

    @app.get("/v1/auth/sessions", dependencies=protected)
    async def auth_sessions(
        limit: int = Query(default=200, ge=1, le=1_000),
    ) -> list[dict[str, Any]]:
        return store.list_auth_sessions(limit=limit)

    @app.delete("/v1/secrets/{credential_id:path}", dependencies=protected)
    async def disable_secret(credential_id: str) -> dict[str, str]:
        normalized = (
            credential_id if credential_id.startswith("secret://") else f"secret://{credential_id}"
        )
        secrets_runtime().disable(normalized)
        return {"status": "disabled", "credential_id": normalized}

    return app
