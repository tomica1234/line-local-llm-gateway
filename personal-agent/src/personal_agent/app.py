from __future__ import annotations

import asyncio
import ipaddress
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import asdict
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr

from .activity import ActivityCaptureService
from .activity.models import ActivityBatch, ActivitySettingsUpdate
from .audit import AuditLogger
from .auth import auth_tools
from .backup import EncryptedBackupService
from .browser import BrowserWorkerClient, browser_tools
from .browser_worker.models import BrowserProfile, TakeoverReleaseRequest
from .calendar import CalendarStore, CalendarSyncService, calendar_tools
from .calendar.models import CalendarEventCreate, CalendarEventUpdate
from .calendar.providers import GoogleCalendarProvider, LocalCalendarProvider
from .coding import CodingService, coding_tools
from .commerce import CommerceStore, commerce_tools
from .communication import CommunicationService, CommunicationStore, communication_tools
from .communication.models import CommunicationSource, NormalizedMessageCreate
from .communication.service import LinePushAdapter, WorkerCommunicationAdapter
from .computer import computer_tools
from .config import Settings
from .contacts import ContactCreate, ContactsStore, contact_tools
from .core.service import AgentService, TaskNotResumable
from .economic import EconomicStore, economic_tools
from .evaluation import (
    BenchmarkRunner,
    BenchmarkRunRequest,
    BenchmarkStore,
    load_default_suite,
)
from .execution import ExecutionStepStatus, ExecutionStore
from .files import FileService, file_tools
from .gateway.line import line_source_id, process_line_event, verify_signature
from .home import HomeAssistantClient, home_tools
from .learning import LearningService, learning_tools
from .line_desktop import LineDesktopBridgeClient
from .line_desktop_bridge.models import SnapshotResponse
from .memory import MemoryStore
from .memory.embedding import LocalEmbeddingClient
from .memory.models import (
    EntityCreate,
    EventCreate,
    MemoryCreate,
    MemoryKind,
    MemoryUpdate,
    PreferenceUpsert,
)
from .memory.tools import memory_tools
from .models.qwen import ModelClient
from .models.registry import LocalModelRouter
from .observability import ObservabilityService
from .personal_data import PersonalDataStore, personal_data_tools
from .personal_data.models import (
    DiaryCreate,
    PersonalTodoCreate,
    PersonalTodoUpdate,
    TodoStatus,
)
from .policy.engine import PolicyEngine
from .portability import DataPortabilityService, DeleteScope, export_json_bytes
from .proactive import ProactiveService
from .routing.deterministic import DeterministicRouter
from .secret.models import SecretPutRequest
from .secret.protection import protector_from_environment
from .storage import Storage
from .strong_auth import StrongAuthService
from .strong_auth.service import StrongAuthRejected, StrongAuthUnavailable
from .tool_broker.broker import ToolBroker
from .tool_broker.builtin import builtin_tools
from .types import (
    Channel as TaskChannel,
)
from .types import HealthResponse, MessageRequest, MessageResponse, RiskLevel, TaskState


class LockUpdate(BaseModel):
    enabled: bool


class NotificationRequest(BaseModel):
    source: str
    conversation_id: str


class ApprovalDecisionRequest(BaseModel):
    approved: bool


class PasskeyRegistrationRequest(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class WebAuthnResponseRequest(BaseModel):
    challenge_id: str = Field(min_length=36, max_length=36)
    credential: dict[str, Any]


class OtpSubmitRequest(BaseModel):
    auth_session_id: str = Field(min_length=8, max_length=128)
    code: SecretStr


class ConnectorUpdate(BaseModel):
    enabled: bool
    scopes: list[str] = Field(default_factory=list, max_length=100)


class ProactiveSettingsUpdate(BaseModel):
    enabled: bool
    categories: dict[str, bool]
    quiet_hours: dict[str, str]
    frequency_minutes: int = Field(default=300, ge=5, le=1_440)


class DataDeleteRequest(BaseModel):
    scope: DeleteScope
    confirmation: str = Field(min_length=8, max_length=64)


class LearningDecisionRequest(BaseModel):
    accepted: bool


class TodoSnoozeRequest(BaseModel):
    until: datetime


class CalendarSyncRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=100)


class FilePathRequest(BaseModel):
    path: str = Field(min_length=1, max_length=8_000)
    pages: list[int] | None = Field(default=None, max_length=500)


class GoogleOAuthConnectRequest(BaseModel):
    account_label: str = Field(default="Google", min_length=1, max_length=200)
    scopes: list[str] = Field(
        default_factory=lambda: [
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.send",
        ],
        min_length=1,
        max_length=10,
    )


class GmailAttachmentDownloadRequest(BaseModel):
    message_id: str = Field(min_length=1, max_length=512)
    attachment_id: str = Field(min_length=1, max_length=2_000)
    filename: str = Field(min_length=1, max_length=500)
    media_type: str = Field(default="application/octet-stream", max_length=500)


class EndpointSecurity(StrEnum):
    LOCAL_ONLY = "LOCAL_ONLY"
    REMOTE_AUTHENTICATED = "REMOTE_AUTHENTICATED"
    ADMIN_ONLY = "ADMIN_ONLY"
    PUBLIC_SIGNED_WEBHOOK = "PUBLIC_SIGNED_WEBHOOK"
    WORKER_TOKEN = "WORKER_TOKEN"


_ADMIN_PATH_PREFIXES = (
    "/api/system/",
    "/api/benchmark/",
    "/api/data/",
    "/api/connectors",
    "/api/economic/",
    "/api/money/",
    "/api/files/status",
    "/api/home/status",
    "/api/learning/",
    "/api/approvals",
    "/api/auth/",
    "/api/secrets",
    "/api/browser/",
    "/api/audit",
)


def endpoint_security(method: str, path: str) -> EndpointSecurity:
    """Return the route's outer security class; route dependencies remain additive."""

    if method == "POST" and path == "/api/channels/line/webhook":
        return EndpointSecurity.PUBLIC_SIGNED_WEBHOOK
    if method == "POST" and path in {
        "/api/activity/batch",
        "/api/channels/line-desktop/ingest",
    }:
        return EndpointSecurity.WORKER_TOKEN
    if path in {"/api/metrics"} or path.startswith(_ADMIN_PATH_PREFIXES):
        return EndpointSecurity.ADMIN_ONLY
    if method in {"POST", "PATCH", "DELETE"} and path.startswith("/api/calendar/"):
        return EndpointSecurity.ADMIN_ONLY
    return EndpointSecurity.REMOTE_AUTHENTICATED


class Runtime:
    def __init__(self, settings: Settings, model: ModelClient):
        self.settings = settings
        self.model_registry = getattr(model, "registry", None)
        self.storage = Storage(settings.db_path)
        self.storage.initialize()
        self.execution = ExecutionStore(self.storage)
        self.execution.initialize()
        self.execution_recovery = self.execution.recover_incomplete()
        self.recovered_tasks = self.storage.recover_incomplete_tasks()
        self.audit = AuditLogger(self.storage)
        self.strong_auth = StrongAuthService(self.storage, settings)
        embedding = None
        if settings.embedding_model_base_url and settings.embedding_model_name:
            settings.validate_model_url(
                settings.embedding_model_base_url,
                variable="PERSONAL_AGENT_EMBEDDING_MODEL_BASE_URL",
            )
            embedding = LocalEmbeddingClient(
                base_url=settings.embedding_model_base_url,
                model_id=settings.embedding_model_name,
            )
        self.memory = MemoryStore(
            self.storage,
            default_raw_retention_days=settings.raw_event_retention_days,
            embedding_provider=embedding,
        )
        self.memory.initialize()
        self.learning = LearningService(self.storage, self.memory, user_id=settings.user_id)
        self.learning.initialize()
        self.activity = ActivityCaptureService(self.storage, self.memory, user_id=settings.user_id)
        self.communication_store = CommunicationStore(self.storage)
        self.communication_store.initialize()
        self.communication = CommunicationService(
            self.communication_store, self.memory, user_id=settings.user_id
        )
        self.calendar = CalendarStore(self.storage, default_timezone=settings.timezone)
        self.calendar.initialize()
        self.calendar_sync = CalendarSyncService(self.calendar)
        self.calendar_sync.register(LocalCalendarProvider(self.calendar))
        self.economic = EconomicStore(self.storage)
        self.economic.initialize()
        self.commerce = CommerceStore(self.storage)
        self.commerce.initialize()
        self.personal_data = PersonalDataStore(
            self.storage,
            user_id=settings.user_id,
            timezone=settings.timezone,
        )
        self.personal_data.initialize()
        self.contacts = ContactsStore(self.storage, user_id=settings.user_id)
        self.contacts.initialize()
        self.coding = CodingService(self.storage, settings)
        self.files = FileService(settings.files_roots, settings.files_trash_root)
        self.home = HomeAssistantClient(
            settings.home_assistant_url,
            settings.home_assistant_token,
            safe_scene_ids=settings.home_assistant_safe_scenes,
        )
        self.proactive = ProactiveService(
            self.storage,
            user_id=settings.user_id,
            timezone=settings.timezone,
        )
        self.proactive.initialize()
        self.observability = ObservabilityService(
            self.storage,
            trash_root=settings.files_trash_root,
            database_quota_bytes=settings.database_quota_bytes,
            trash_quota_bytes=settings.trash_quota_bytes,
        )
        self.portability = DataPortabilityService(self.storage, user_id=settings.user_id)
        self.line_push: LinePushAdapter | None = None
        if settings.line_channel_access_token and settings.line_primary_user_id:
            self.line_push = LinePushAdapter(
                access_token=settings.line_channel_access_token,
                primary_user_id=settings.line_primary_user_id,
            )
            self.communication.register(self.line_push, scopes=["messages.read", "messages.write"])
            self.storage.configure_notification_delivery(
                provider="line", target=settings.line_primary_user_id
            )
        self.line_desktop: LineDesktopBridgeClient | None = None
        self.line_desktop_status: dict[str, Any] = {
            "configured": False,
            "last_sync_at": None,
            "last_error": None,
            "stored": 0,
        }
        if settings.line_desktop_bridge_token:
            self.line_desktop = LineDesktopBridgeClient(settings)
            line_desktop_scopes = ["messages.read"]
            if settings.line_desktop_send_enabled:
                line_desktop_scopes.append("messages.write")
            self.communication.register(self.line_desktop, scopes=line_desktop_scopes)
            self.line_desktop_status["configured"] = True
        self.browser = BrowserWorkerClient(settings)
        google_refs = (
            settings.google_refresh_credential_id,
            settings.google_client_id_credential_id,
            settings.google_client_secret_credential_id,
        )
        if settings.browser_worker_token and all(google_refs):
            self.calendar_sync.register(
                GoogleCalendarProvider(
                    self.browser,
                    refresh_credential_id=settings.google_refresh_credential_id,
                    client_id_credential_id=settings.google_client_id_credential_id,
                    client_secret_credential_id=settings.google_client_secret_credential_id,
                    calendar_id=settings.google_calendar_id,
                )
            )
        if settings.browser_worker_token and settings.slack_credential_id:
            self.communication.register(
                WorkerCommunicationAdapter(
                    source=CommunicationSource.SLACK,
                    provider="slack",
                    credential_id=settings.slack_credential_id,
                    worker=self.browser,
                ),
                scopes=["messages.read", "messages.write"],
            )
        gmail_credential_id = settings.google_refresh_credential_id or settings.gmail_credential_id
        if settings.browser_worker_token and gmail_credential_id:
            self.communication.register(
                WorkerCommunicationAdapter(
                    source=CommunicationSource.EMAIL,
                    provider="gmail",
                    credential_id=gmail_credential_id,
                    worker=self.browser,
                    oauth_client_id_credential_id=(
                        settings.google_client_id_credential_id
                        if settings.google_refresh_credential_id
                        else None
                    ),
                    oauth_client_secret_credential_id=(
                        settings.google_client_secret_credential_id
                        if settings.google_refresh_credential_id
                        else None
                    ),
                ),
                scopes=["messages.read", "messages.write"],
            )
        self.policy = PolicyEngine(self.storage)
        self.broker = ToolBroker(self.storage, self.policy, self.audit)
        for definition in builtin_tools(self.storage):
            self.broker.register(definition)
        for definition in memory_tools(self.memory, user_id=settings.user_id):
            self.broker.register(definition)
        for definition in learning_tools(self.learning):
            self.broker.register(definition)
        for definition in browser_tools(self.browser, model):
            self.broker.register(definition)
        for definition in auth_tools(self.browser):
            self.broker.register(definition)
        for definition in communication_tools(self.communication):
            self.broker.register(definition)
        for definition in calendar_tools(self.calendar, self.calendar_sync):
            self.broker.register(definition)
        for definition in economic_tools(self.economic):
            self.broker.register(definition)
        for definition in commerce_tools(self.commerce):
            self.broker.register(definition)
        for definition in personal_data_tools(self.personal_data):
            self.broker.register(definition)
        for definition in contact_tools(self.contacts):
            self.broker.register(definition)
        for definition in file_tools(self.files, model):
            self.broker.register(definition)
        for definition in home_tools(self.home):
            self.broker.register(definition)
        for definition in computer_tools(self.storage, settings):
            self.broker.register(definition)
        for definition in coding_tools(self.coding):
            self.broker.register(definition)
        self.service = AgentService(
            storage=self.storage,
            router=DeterministicRouter(settings.timezone),
            broker=self.broker,
            model=model,
            audit=self.audit,
            memory=self.memory,
            user_id=settings.user_id,
            timezone=settings.timezone,
            execution=self.execution,
            task_cancel_handlers=(self.coding.cancel_task,),
        )
        self.benchmark_store = BenchmarkStore(self.storage)
        self.benchmark_store.initialize()
        capabilities = {
            "core",
            "model",
            "calendar",
            "communication",
            "memory",
            "economic",
            "commerce",
            "personal_todo",
            "diary",
            "contacts",
            "scheduler",
            "proactive",
        }
        if settings.browser_worker_token:
            capabilities |= {"browser_worker", "secret_broker"}
        if settings.files_roots:
            capabilities.add("files")
        if settings.home_assistant_url and settings.home_assistant_token:
            capabilities.add("home_assistant")
        self.benchmark = BenchmarkRunner(
            self.service,
            self.storage,
            self.benchmark_store,
            capabilities=capabilities,
        )
        self.benchmark_lock = asyncio.Lock()


async def deliver_line_notification_once(runtime: Runtime) -> bool:
    adapter = runtime.line_push
    if adapter is None:
        return False
    target = runtime.settings.line_primary_user_id
    delivery = runtime.storage.claim_notification_delivery(provider="line", target=target)
    if delivery is None:
        return False
    delivery_id = str(delivery["delivery_id"])
    attempts = int(delivery["attempts"])
    audit_details = {
        "delivery_id": delivery_id,
        "notification_id": delivery["notification_id"],
        "attempts": attempts,
        "provider": "line",
    }
    try:
        result = await adapter.send(
            conversation_id=target,
            subject="",
            text=str(delivery["text"]),
            thread_id=None,
            reply_to=None,
            idempotency_key=(f"notification:{delivery['notification_id']}:line:{target}"),
            task_id=str(delivery["task_id"]),
            action_id=delivery_id,
        )
    except httpx.HTTPStatusError as exc:
        runtime.storage.complete_notification_delivery(
            delivery_id,
            status="failed",
            error=f"LINE_HTTP_{exc.response.status_code}",
        )
        runtime.audit.record(
            task_id=str(delivery["task_id"]),
            actor="scheduler:line",
            action="notification.deliver",
            result="failed",
            details={**audit_details, "reason_code": f"LINE_HTTP_{exc.response.status_code}"},
        )
        return True
    except Exception as exc:
        result = {
            "status": "submitted_unknown",
            "error": type(exc).__name__,
        }

    if result.get("status") == "ok" and result.get("verified"):
        external_id = str(result.get("external_message_id") or "") or None
        runtime.storage.complete_notification_delivery(
            delivery_id, status="delivered", external_id=external_id
        )
        runtime.audit.record(
            task_id=str(delivery["task_id"]),
            actor="scheduler:line",
            action="notification.deliver",
            result="ok",
            details={**audit_details, "external_id": external_id},
        )
        return True

    reason = str(result.get("error") or result.get("status") or "LINE_UNVERIFIED")[:160]
    if result.get("status") == "submitted_unknown" and attempts < 5:
        delay_seconds = min(2**attempts, 60)
        runtime.storage.retry_notification_delivery(
            delivery_id, delay_seconds=delay_seconds, error=reason
        )
        terminal_status = "retrying"
    else:
        terminal_status = (
            "submitted_unknown" if result.get("status") == "submitted_unknown" else "failed"
        )
        runtime.storage.complete_notification_delivery(
            delivery_id, status=terminal_status, error=reason
        )
    runtime.audit.record(
        task_id=str(delivery["task_id"]),
        actor="scheduler:line",
        action="notification.deliver",
        result=terminal_status,
        details={**audit_details, "reason_code": reason},
    )
    return True


async def sync_line_desktop_once(runtime: Runtime) -> dict[str, Any]:
    client = runtime.line_desktop
    if client is None:
        return {"received": 0, "stored": 0}
    messages = await client.sync_visible()
    stored = sum(runtime.communication.ingest(message) for message in messages)
    result = {"received": len(messages), "stored": stored}
    runtime.line_desktop_status.update(
        {
            "last_sync_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "last_error": None,
            "stored": int(runtime.line_desktop_status.get("stored", 0)) + stored,
        }
    )
    if stored:
        runtime.audit.record(
            task_id=None,
            actor="scheduler:line-desktop",
            action="communication.sync.visible",
            result="ok",
            details=result,
        )
    return result


def ingest_line_desktop_snapshot(runtime: Runtime, snapshot: SnapshotResponse) -> dict[str, Any]:
    messages = [
        LineDesktopBridgeClient.normalized_message(item.model_dump(mode="json"))
        for item in snapshot.messages
    ]
    stored = sum(runtime.communication.ingest(message) for message in messages)
    result = {"received": len(messages), "stored": stored}
    runtime.line_desktop_status.update(
        {
            "last_sync_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "last_error": None,
            "stored": int(runtime.line_desktop_status.get("stored", 0)) + stored,
            "visible_chat_count": snapshot.visible_chat_count,
            "session_state": snapshot.session_state,
            "capture_mode": "memory_only_windows_ocr",
            "screenshots_persisted": snapshot.screenshot_persisted,
            "may_mark_read": snapshot.may_mark_read,
        }
    )
    if stored:
        runtime.audit.record(
            task_id=None,
            actor="bridge:line-desktop",
            action="communication.push.visible",
            result="ok",
            details=result,
        )
    return result


def create_app(
    settings: Settings | None = None, model_client: ModelClient | None = None
) -> FastAPI:
    configured = settings or Settings.from_env()
    configured.validate_bind_host()
    configured.validate_remote_bind_security()
    model = model_client or LocalModelRouter.from_settings(configured)
    runtime = Runtime(configured, model)

    async def retention_loop() -> None:
        while True:
            await asyncio.sleep(3600)
            local_now = datetime.now(runtime.service.timezone)
            previous_day = (local_now - timedelta(days=1)).date()
            day_start = datetime.combine(
                previous_day,
                datetime.min.time(),
                tzinfo=runtime.service.timezone,
            )
            summary = runtime.memory.summarize_period(
                user_id=configured.user_id,
                summary_key=f"daily:{previous_day.isoformat()}",
                start_at=day_start,
                end_at=day_start + timedelta(days=1),
            )
            decayed = runtime.memory.decay_memories(
                user_id=configured.user_id,
                before=datetime.now(UTC) - timedelta(days=180),
            )
            workflows = runtime.learning.mine_workflows()
            result = runtime.memory.purge_expired()
            quota_task_id = runtime.observability.queue_quota_warning(user_id=configured.user_id)
            if (
                summary
                or decayed
                or workflows
                or quota_task_id
                or result["events"]
                or result["memories"]
            ):
                runtime.audit.record(
                    task_id=None,
                    actor="scheduler",
                    action="memory.retention.purge",
                    result="ok",
                    details={
                        **result,
                        "summary_memory_id": summary.memory_id if summary else None,
                        "decayed_memories": decayed,
                        "workflow_candidates": len(workflows),
                        "quota_warning_task_id": quota_task_id,
                    },
                )

    async def proactive_loop() -> None:
        while True:
            frequency = runtime.proactive.settings()["frequency_minutes"]
            await asyncio.sleep(int(frequency) * 60)
            created = runtime.proactive.scan()
            if created:
                runtime.audit.record(
                    task_id=None,
                    actor="scheduler",
                    action="proactive.scan",
                    result="ok",
                    details={
                        "created": len(created),
                        "opportunity_ids": [item["opportunity_id"] for item in created],
                    },
                )

    async def backup_loop() -> None:
        assert configured.backup_root is not None
        while True:
            try:
                service = EncryptedBackupService(protector_from_environment())
                result = await asyncio.to_thread(
                    service.create_automated,
                    configured.db_path,
                    configured.backup_root,
                    retention_count=configured.backup_retention_count,
                    retention_days=configured.backup_retention_days,
                )
                runtime.audit.record(
                    task_id=None,
                    actor="scheduler",
                    action="backup.automated",
                    result="ok",
                    details={
                        "destination": result["destination"],
                        "verified": result["verification"]["verified"],
                        "pruned_count": len(result["pruned"]),
                    },
                )
            except Exception as exc:
                runtime.audit.record(
                    task_id=None,
                    actor="scheduler",
                    action="backup.automated",
                    result="failed",
                    details={"reason_code": type(exc).__name__},
                )
            await asyncio.sleep(max(1, configured.backup_interval_hours) * 3600)

    async def line_notification_loop() -> None:
        while True:
            handled = await deliver_line_notification_once(runtime)
            if not handled:
                await asyncio.sleep(1)

    async def coding_job_loop() -> None:
        while True:
            try:
                runtime.coding.refresh_jobs()
            except Exception as exc:
                runtime.audit.record(
                    task_id=None,
                    actor="scheduler",
                    action="coding.refresh",
                    result="failed",
                    details={"reason_code": type(exc).__name__},
                )
            for job in runtime.coding.pending_notifications():
                try:
                    job_status = str(job["status"])
                    current_task = runtime.storage.get_task(str(job["task_id"]))
                    if current_task.state is TaskState.CANCELLED:
                        runtime.coding.cancel_task(current_task.task_id)
                        runtime.coding.schedule_completion_notification(job)
                        continue
                    step_id = job.get("step_id")
                    if step_id:
                        step_status = (
                            ExecutionStepStatus.COMPLETED
                            if job_status == "completed"
                            else ExecutionStepStatus.SUBMITTED_UNKNOWN
                            if job_status == "submitted_unknown"
                            else ExecutionStepStatus.FAILED
                        )
                        runtime.execution.set_status(
                            str(job["task_id"]),
                            str(step_id),
                            step_status,
                            evidence={"coding_job_id": job["job_id"], "status": job_status},
                        )
                    has_remaining = any(
                        step.status is not ExecutionStepStatus.COMPLETED
                        for step in runtime.execution.steps(str(job["task_id"]))
                    )
                    task_state = (
                        (TaskState.PAUSED if has_remaining else TaskState.COMPLETED)
                        if job_status == "completed"
                        else TaskState.SUBMITTED_UNKNOWN
                        if job_status == "submitted_unknown"
                        else TaskState.FAILED
                    )
                    runtime.storage.update_task(
                        str(job["task_id"]),
                        state=task_state,
                        result={"coding_job_id": job["job_id"], "status": job_status},
                        event_type="coding_job_finished",
                    )
                    runtime.coding.schedule_completion_notification(job)
                except Exception as exc:
                    runtime.audit.record(
                        task_id=str(job.get("task_id") or "") or None,
                        actor="scheduler",
                        action="coding.completion",
                        result="failed",
                        details={
                            "coding_job_id": job.get("job_id"),
                            "reason_code": type(exc).__name__,
                        },
                    )
            await asyncio.sleep(2)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        runtime.memory.purge_expired()
        background_tasks = [
            asyncio.create_task(retention_loop()),
            asyncio.create_task(proactive_loop()),
            asyncio.create_task(coding_job_loop()),
        ]
        if runtime.line_push is not None:
            background_tasks.append(asyncio.create_task(line_notification_loop()))
        if configured.backup_root is not None:
            background_tasks.append(asyncio.create_task(backup_loop()))
        try:
            yield
        finally:
            for task in background_tasks:
                task.cancel()
            for task in background_tasks:
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(
        title="Local Personal Agent",
        version="0.1.0",
        description="Local-first shared Task Core for Voice, LINE, and Web.",
        lifespan=lifespan,
    )
    app.state.runtime = runtime

    def passkey_session(request: Request) -> dict[str, Any] | None:
        return runtime.strong_auth.authenticate_session(
            request.cookies.get(runtime.strong_auth.cookie_name)
        )

    def require_admin(
        request: Request,
        x_admin_token: Annotated[str | None, Header()] = None,
    ) -> None:
        if passkey_session(request):
            return
        if not configured.admin_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="PERSONAL_AGENT_ADMIN_TOKEN is not configured",
            )
        if not x_admin_token or not secrets.compare_digest(x_admin_token, configured.admin_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin token"
            )

    def require_passkey(request: Request) -> dict[str, Any]:
        session = passkey_session(request)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Face ID or Windows Hello passkey authentication is required",
            )
        return session

    def require_enrollment_authority(
        request: Request,
        x_admin_token: Annotated[str | None, Header()] = None,
    ) -> None:
        if runtime.strong_auth.credential_count() == 0:
            require_admin(request, x_admin_token)
            return
        require_passkey(request)

    def require_activity_token(
        x_activity_token: Annotated[str | None, Header()] = None,
    ) -> None:
        if not configured.activity_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="PERSONAL_AGENT_ACTIVITY_TOKEN is not configured",
            )
        if not x_activity_token or not secrets.compare_digest(
            x_activity_token, configured.activity_token
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid activity token",
            )

    def require_line_desktop_token(
        x_line_desktop_token: Annotated[str | None, Header()] = None,
    ) -> None:
        if not configured.line_desktop_bridge_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LINE Desktop Bridge is not configured",
            )
        if not x_line_desktop_token or not secrets.compare_digest(
            x_line_desktop_token, configured.line_desktop_bridge_token
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid LINE Desktop Bridge token",
            )

    def is_loopback_connection(connection: Request | WebSocket) -> bool:
        if connection.client is None:
            return False
        if connection.client.host == "testclient" and configured.host in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            return True
        try:
            return ipaddress.ip_address(connection.client.host).is_loopback
        except ValueError:
            return connection.client.host.casefold() == "localhost"

    peer_identities = {
        str(ipaddress.ip_address(address)): identity
        for address, identity in configured.tailscale_peer_identities
    }

    def is_trusted_tls_proxy(connection: Request | WebSocket) -> bool:
        return is_loopback_connection(connection) and (
            connection.headers.get("X-Personal-Agent-Remote-Proxy") == "tailscale-direct-tls-v1"
        )

    def is_trusted_tailscale_serve(connection: Request | WebSocket) -> bool:
        # Tailscale Serve reaches a loopback-bound backend and injects this header. A remote
        # socket can never select this branch, and direct binds ignore the header entirely.
        return (
            is_loopback_connection(connection)
            and not connection.headers.get("X-Personal-Agent-Remote-Proxy")
            and bool(connection.headers.get("Tailscale-User-Login", "").strip())
        )

    def is_remote_connection(connection: Request | WebSocket) -> bool:
        return (
            not is_loopback_connection(connection)
            or is_trusted_tls_proxy(connection)
            or is_trusted_tailscale_serve(connection)
        )

    def trusted_remote_identity(connection: Request | WebSocket) -> str | None:
        if is_trusted_tls_proxy(connection):
            forwarded = connection.headers.get("X-Forwarded-For", "").strip()
            try:
                forwarded_address = ipaddress.ip_address(forwarded)
            except ValueError:
                return None
            if forwarded_address not in ipaddress.ip_network("100.64.0.0/10"):
                return None
            identity = connection.headers.get("Tailscale-User-Login", "").strip().casefold()
            return identity if identity in configured.tailscale_allowed_users else None
        if is_trusted_tailscale_serve(connection):
            identity = connection.headers.get("Tailscale-User-Login", "").strip().casefold()
            return identity if identity in configured.tailscale_allowed_users else None
        if connection.client is None:
            return None
        try:
            address = str(ipaddress.ip_address(connection.client.host))
        except ValueError:
            return None
        identity = peer_identities.get(address)
        return identity if identity in configured.tailscale_allowed_users else None

    remote_passkey_exempt_paths = {
        "/api/health",
        "/api/webauthn/status",
        "/api/webauthn/register/options",
        "/api/webauthn/register/verify",
        "/api/webauthn/login/options",
        "/api/webauthn/login/verify",
        "/api/webauthn/logout",
    }

    @app.exception_handler(KeyError)
    async def key_error_handler(_request: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": f"Not found: {exc.args[0]}"})

    @app.exception_handler(TaskNotResumable)
    async def task_conflict_handler(_request: Request, exc: TaskNotResumable) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(StrongAuthUnavailable)
    async def strong_auth_unavailable_handler(
        _request: Request, exc: StrongAuthUnavailable
    ) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.exception_handler(StrongAuthRejected)
    async def strong_auth_rejected_handler(
        _request: Request, exc: StrongAuthRejected
    ) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response
        security_class = endpoint_security(request.method, request.url.path)
        remote_request = is_remote_connection(request)
        if remote_request and security_class is not EndpointSecurity.PUBLIC_SIGNED_WEBHOOK:
            if security_class is EndpointSecurity.LOCAL_ONLY:
                response = JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "This endpoint is available on loopback only"},
                )
            elif security_class is EndpointSecurity.WORKER_TOKEN:
                response = await call_next(request)
            elif (identity := trusted_remote_identity(request)) is None:
                response = JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "A trusted Tailscale identity is required"},
                )
            elif not configured.require_remote_passkey or not configured.webauthn_rp_id:
                response = JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"detail": "Remote passkey enforcement is not safely configured"},
                )
            elif (
                request.url.path.startswith("/api/")
                and request.url.path not in remote_passkey_exempt_paths
                and passkey_session(request) is None
            ):
                response = JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "detail": (
                            "Face ID or Windows Hello passkey sign-in is required "
                            "for remote API access"
                        )
                    },
                )
            else:
                request.state.remote_identity = identity
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["X-Personal-Agent-Security-Class"] = security_class.value
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; object-src 'none'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; manifest-src 'self'"
        )
        response.headers["Permissions-Policy"] = (
            "publickey-credentials-create=(self), publickey-credentials-get=(self), "
            "camera=(), geolocation=(), microphone=()"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if runtime.strong_auth.secure_cookie:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            database=str(configured.db_path),
            model_endpoint=configured.model_base_url,
            recovered_tasks=runtime.recovered_tasks,
        )

    @app.get("/api/system/health", dependencies=[Depends(require_admin)])
    async def system_health() -> dict[str, Any]:
        return runtime.observability.health()

    @app.get("/api/models", dependencies=[Depends(require_admin)])
    async def models() -> dict[str, Any]:
        return (
            runtime.model_registry.snapshot()
            if runtime.model_registry
            else {"custom": {"model_id": str(getattr(model, "model", type(model).__name__))}}
        )

    @app.get("/api/metrics", dependencies=[Depends(require_admin)])
    async def metrics() -> dict[str, Any]:
        return runtime.observability.metrics()

    @app.get("/api/benchmark/cases", dependencies=[Depends(require_admin)])
    async def benchmark_cases() -> dict[str, Any]:
        suite_version, cases = load_default_suite()
        return {
            "suite_version": suite_version,
            "cases": [item.model_dump(mode="json") for item in cases],
            "capabilities": sorted(runtime.benchmark.capabilities),
        }

    @app.post("/api/benchmark/run", dependencies=[Depends(require_admin)])
    async def run_benchmark(request: BenchmarkRunRequest) -> dict[str, Any]:
        if runtime.benchmark_lock.locked():
            raise HTTPException(status_code=409, detail="A benchmark run is already active")
        suite_version, cases = load_default_suite()
        if request.case_ids:
            requested = set(request.case_ids)
            known = {item.case_id for item in cases}
            unknown = requested - known
            if unknown:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown benchmark cases: {', '.join(sorted(unknown))}",
                )
            cases = [item for item in cases if item.case_id in requested]
        async with runtime.benchmark_lock:
            report = await runtime.benchmark.run(
                cases,
                suite_version=suite_version,
                trials=request.trials,
            )
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="benchmark.run",
            result="ok",
            details={
                "run_id": report.run_id,
                "overall_score": report.overall_score,
                "policy_violations": report.policy_violations,
            },
        )
        return report.model_dump(mode="json")

    @app.get("/api/benchmark/runs", dependencies=[Depends(require_admin)])
    async def benchmark_runs(
        limit: int = Query(default=20, ge=1, le=100),
    ) -> list[dict[str, Any]]:
        return runtime.benchmark_store.list(limit=limit)

    @app.get("/api/benchmark/runs/{run_id}", dependencies=[Depends(require_admin)])
    async def benchmark_report(run_id: str) -> dict[str, Any]:
        return runtime.benchmark_store.get(run_id).model_dump(mode="json")

    @app.get("/api/data/export", dependencies=[Depends(require_admin)])
    async def export_data() -> Response:
        payload = export_json_bytes(runtime.portability)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="data.export",
            result="ok",
            details={"bytes": len(payload), "secret_values_included": False},
        )
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return Response(
            content=payload,
            media_type="application/json",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="personal-agent-export-{timestamp}.json"'
                ),
                "Cache-Control": "no-store",
            },
        )

    @app.post("/api/data/delete", dependencies=[Depends(require_admin)])
    async def delete_data(request: DataDeleteRequest) -> dict[str, Any]:
        result = runtime.portability.delete(request.scope, confirmation=request.confirmation)
        if request.scope == "all":
            runtime.economic.initialize()
            runtime.proactive.initialize()
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="data.delete",
            result="ok",
            details=result,
        )
        return result

    @app.post("/api/messages", response_model=MessageResponse)
    async def message(request: MessageRequest) -> MessageResponse:
        return await runtime.service.handle_message(request)

    @app.post("/api/events", dependencies=[Depends(require_admin)])
    async def append_event(event: EventCreate) -> dict[str, Any]:
        record = runtime.memory.append_event(user_id=configured.user_id, event=event)
        return {
            "stored": record is not None,
            "event": record.model_dump(mode="json") if record else None,
        }

    @app.post("/api/activity/batch", dependencies=[Depends(require_activity_token)])
    async def capture_activity(batch: ActivityBatch) -> dict[str, Any]:
        result = runtime.activity.capture(batch)
        return asdict(result)

    @app.get("/api/activity/status")
    async def activity_status() -> dict[str, object]:
        return runtime.activity.status()

    @app.put("/api/activity/status", dependencies=[Depends(require_admin)])
    async def update_activity_status(
        update: ActivitySettingsUpdate,
    ) -> dict[str, object]:
        result = runtime.activity.update_settings(
            enabled=update.enabled, blocked_domains=update.blocked_domains
        )
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="activity_capture.settings",
            result="ok",
            details=result,
        )
        return result

    @app.get("/api/events")
    async def events(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
        return [
            event.model_dump(mode="json")
            for event in runtime.memory.list_events(user_id=configured.user_id, limit=limit)
        ]

    @app.get("/api/search")
    async def personal_search(
        q: str = Query(min_length=1, max_length=2_000),
        limit: int = Query(50, ge=1, le=100),
    ) -> list[dict[str, Any]]:
        return [
            hit.model_dump(mode="json")
            for hit in runtime.memory.personal_search(
                user_id=configured.user_id, query=q, limit=limit
            )
        ]

    @app.get("/api/memories")
    async def memories(
        kind: MemoryKind | None = None,
        limit: int = Query(100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        return [
            memory.model_dump(mode="json")
            for memory in runtime.memory.list_memories(
                user_id=configured.user_id, kind=kind, limit=limit
            )
        ]

    @app.post("/api/memories")
    async def remember(memory: MemoryCreate) -> dict[str, Any]:
        result = runtime.memory.remember(user_id=configured.user_id, memory=memory)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="memory.remember",
            result="ok",
            details={"memory_id": result.memory_id, "kind": result.kind.value},
        )
        return result.model_dump(mode="json")

    @app.patch("/api/memories/{memory_id}")
    async def update_memory(memory_id: str, update: MemoryUpdate) -> dict[str, Any]:
        result = runtime.memory.update_memory(memory_id, update)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="memory.update",
            result="ok",
            details={"memory_id": memory_id},
        )
        return result.model_dump(mode="json")

    @app.delete("/api/memories/{memory_id}")
    async def delete_memory(memory_id: str) -> dict[str, str]:
        runtime.memory.delete_memory(user_id=configured.user_id, memory_id=memory_id)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="memory.forget",
            result="ok",
            details={"memory_id": memory_id},
        )
        return {"status": "deleted"}

    @app.get("/api/preferences")
    async def preferences() -> list[dict[str, Any]]:
        return runtime.memory.list_preferences(user_id=configured.user_id)

    @app.put("/api/preferences")
    async def upsert_preference(preference: PreferenceUpsert) -> dict[str, Any]:
        return runtime.memory.upsert_preference(user_id=configured.user_id, preference=preference)

    @app.post("/api/entities")
    async def create_entity(entity: EntityCreate) -> dict[str, Any]:
        return runtime.memory.create_entity(user_id=configured.user_id, entity=entity)

    @app.post("/api/memory/retention/purge", dependencies=[Depends(require_admin)])
    async def purge_memory_retention() -> dict[str, int]:
        result = runtime.memory.purge_expired()
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="memory.retention.purge",
            result="ok",
            details=result,
        )
        return result

    @app.post("/api/channels/voice/input", response_model=MessageResponse)
    async def voice_input(request: MessageRequest) -> MessageResponse:
        normalized = MessageRequest.model_validate({**request.model_dump(), "source": "voice"})
        return await runtime.service.handle_message(normalized)

    @app.websocket("/api/channels/voice/ws")
    async def voice_websocket(websocket: WebSocket) -> None:
        if is_remote_connection(websocket):
            if trusted_remote_identity(websocket) is None:
                await websocket.close(code=1008, reason="Trusted Tailscale identity is required")
                return
            session_token = websocket.cookies.get(runtime.strong_auth.cookie_name)
            if (
                not configured.require_remote_passkey
                or not configured.webauthn_rp_id
                or runtime.strong_auth.authenticate_session(session_token) is None
            ):
                await websocket.close(code=1008, reason="Passkey sign-in is required")
                return
        await websocket.accept()
        try:
            while True:
                payload = await websocket.receive_json()
                payload["source"] = "voice"
                request = MessageRequest.model_validate(payload)
                response = await runtime.service.handle_message(request)
                await websocket.send_json(response.model_dump(mode="json"))
        except WebSocketDisconnect:
            return
        except Exception as exc:
            await websocket.send_json({"error": type(exc).__name__, "detail": str(exc)})
            await websocket.close(code=1011)

    @app.post("/api/channels/line/webhook")
    async def line_webhook(
        request: Request,
        background_tasks: BackgroundTasks,
        x_line_signature: Annotated[str | None, Header()] = None,
    ) -> dict[str, str]:
        if not all(
            (
                configured.line_channel_secret,
                configured.line_channel_access_token,
                configured.line_primary_user_id,
            )
        ):
            raise HTTPException(status_code=503, detail="LINE connector is not fully configured")
        body = await request.body()
        if not x_line_signature or not verify_signature(
            body, x_line_signature, configured.line_channel_secret
        ):
            raise HTTPException(status_code=401, detail="Invalid LINE signature")
        payload = await request.json()
        for event in payload.get("events", []):
            source = event.get("source", {})
            if source.get("userId") != configured.line_primary_user_id:
                runtime.audit.record(
                    task_id=None,
                    actor="gateway:line",
                    action="event.authorize",
                    result="denied",
                    details={"reason_code": "NOT_PRIMARY_USER"},
                )
                continue
            if event.get("type") != "message" or event.get("message", {}).get("type") != "text":
                continue
            event_id = event.get("webhookEventId") or event.get("message", {}).get("id")
            if not event_id or not runtime.storage.claim_inbound_event(
                source="line", external_event_id=event_id
            ):
                continue
            timestamp_ms = event.get("timestamp")
            timestamp = (
                datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC).isoformat()
                if isinstance(timestamp_ms, (int, float))
                else datetime.now(UTC).isoformat()
            )
            runtime.communication.ingest(
                NormalizedMessageCreate(
                    message_id=str(event.get("message", {}).get("id") or event_id),
                    source=CommunicationSource.LINE,
                    conversation_id=line_source_id(source) or "line",
                    thread_id=None,
                    timestamp=timestamp,
                    text=event["message"]["text"],
                    permissions=["messages.read", "messages.reply"],
                    source_reference=f"line://message/{event_id}",
                )
            )
            background_tasks.add_task(
                process_line_event,
                event=event,
                service=runtime.service,
                storage=runtime.storage,
                audit=runtime.audit,
                access_token=configured.line_channel_access_token,
            )
        return {"status": "accepted"}

    @app.get("/api/channels/line/status", dependencies=[Depends(require_admin)])
    async def line_status() -> dict[str, Any]:
        return {
            "configured": bool(
                configured.line_channel_secret
                and configured.line_channel_access_token
                and configured.line_primary_user_id
            ),
            "push_enabled": runtime.line_push is not None,
            "primary_user_restricted": bool(configured.line_primary_user_id),
            "webhook_path": "/api/channels/line/webhook",
        }

    @app.get("/api/channels/line-desktop/status", dependencies=[Depends(require_admin)])
    async def line_desktop_status() -> dict[str, Any]:
        status_payload = dict(runtime.line_desktop_status)
        status_payload["send_enabled"] = configured.line_desktop_send_enabled
        bridge_status = "waiting"
        last_sync_age_seconds = None
        if status_payload.get("last_sync_at"):
            try:
                last_sync = datetime.fromisoformat(str(status_payload["last_sync_at"]))
                last_sync_age_seconds = max(0, int((datetime.now(UTC) - last_sync).total_seconds()))
                if last_sync_age_seconds <= configured.line_desktop_sync_interval_seconds * 3:
                    bridge_status = "ok"
                else:
                    bridge_status = "stale"
            except ValueError:
                bridge_status = "unknown"
        status_payload["bridge"] = {
            "status": bridge_status,
            "mode": "outbound_push",
            "sync_interval_seconds": configured.line_desktop_sync_interval_seconds,
            "last_sync_age_seconds": last_sync_age_seconds,
        }
        return status_payload

    @app.post(
        "/api/channels/line-desktop/ingest",
        dependencies=[Depends(require_line_desktop_token)],
    )
    async def line_desktop_ingest(snapshot: SnapshotResponse) -> dict[str, Any]:
        return ingest_line_desktop_snapshot(runtime, snapshot)

    @app.post(
        "/api/channels/line-desktop/sync",
        dependencies=[Depends(require_admin)],
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def line_desktop_sync() -> dict[str, Any]:
        if runtime.line_desktop is None:
            raise HTTPException(status_code=503, detail="LINE Desktop Bridge is not configured")
        return {
            "status": "managed_by_windows_bridge",
            "sync_interval_seconds": configured.line_desktop_sync_interval_seconds,
        }

    @app.get("/api/tasks")
    async def tasks(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
        return [task.model_dump(mode="json") for task in runtime.storage.list_tasks(limit=limit)]

    @app.get("/api/today")
    async def today() -> dict[str, Any]:
        local_now = datetime.now(runtime.service.timezone)
        day_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        todos = runtime.personal_data.list_todos(status=TodoStatus.OPEN, limit=500)
        return {
            "date": local_now.date().isoformat(),
            "timezone": str(runtime.service.timezone),
            "calendar": [
                item.model_dump(mode="json")
                for item in runtime.calendar.search(
                    query=None,
                    start_at=day_start,
                    end_at=day_end,
                    limit=500,
                )
            ],
            "must": [
                item.model_dump(mode="json") for item in todos if item.todo_type.value == "must"
            ],
            "want": [
                item.model_dump(mode="json") for item in todos if item.todo_type.value == "want"
            ],
            "reminders": [
                item
                for item in runtime.storage.list_scheduled_jobs()
                if item["status"] == "scheduled" and item["run_at"] < day_end.isoformat()
            ],
            "suggestions": runtime.proactive.list(state="open", limit=20),
            "generated_at": local_now.isoformat(),
        }

    @app.get("/api/todos")
    async def todos(
        todo_status: Annotated[TodoStatus | None, Query(alias="status")] = TodoStatus.OPEN,
        limit: int = Query(default=200, ge=1, le=1_000),
    ) -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json")
            for item in runtime.personal_data.list_todos(status=todo_status, limit=limit)
        ]

    @app.post("/api/todos")
    async def create_todo(value: PersonalTodoCreate) -> dict[str, Any]:
        result = runtime.personal_data.create_todo(value)
        runtime.audit.record(
            task_id=result.source_task_id,
            actor="primary_user:web",
            action="todo.create",
            result="ok",
            details={"todo_id": result.todo_id, "reminder_scheduled": bool(result.remind_at)},
        )
        return result.model_dump(mode="json")

    @app.patch("/api/todos/{todo_id}")
    async def update_todo(todo_id: str, value: PersonalTodoUpdate) -> dict[str, Any]:
        result = runtime.personal_data.update_todo(todo_id, value)
        return result.model_dump(mode="json")

    @app.post("/api/todos/{todo_id}/complete")
    async def complete_todo(todo_id: str) -> dict[str, Any]:
        return runtime.personal_data.complete_todo(todo_id).model_dump(mode="json")

    @app.post("/api/todos/{todo_id}/snooze")
    async def snooze_todo(todo_id: str, request: TodoSnoozeRequest) -> dict[str, Any]:
        return runtime.personal_data.snooze_todo(todo_id, until=request.until).model_dump(
            mode="json"
        )

    @app.delete("/api/todos/{todo_id}")
    async def delete_todo(todo_id: str) -> dict[str, Any]:
        return runtime.personal_data.delete_todo(todo_id)

    @app.get("/api/diary")
    async def diary_entries(
        entry_date: Annotated[date | None, Query(alias="date")] = None,
        q: str | None = Query(default=None, max_length=2_000),
    ) -> list[dict[str, Any]]:
        entries = (
            runtime.personal_data.search_diary(q, limit=200)
            if q
            else runtime.personal_data.read_diary(entry_date)
        )
        return [item.model_dump(mode="json") for item in entries]

    @app.post("/api/diary")
    async def create_diary_entry(value: DiaryCreate) -> dict[str, Any]:
        return runtime.personal_data.create_diary(value).model_dump(mode="json")

    @app.get("/api/inbox")
    async def inbox(limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json") for item in runtime.communication_store.recent(limit=limit)
        ]

    @app.get("/api/contacts")
    async def contacts(
        q: str = Query(default="", max_length=2_000),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        records = (
            runtime.contacts.search(q, limit=limit)
            if q.strip()
            else runtime.contacts.list(limit=limit)
        )
        return [item.model_dump(mode="json") for item in records]

    @app.post("/api/contacts")
    async def create_contact(value: ContactCreate) -> dict[str, Any]:
        return runtime.contacts.upsert(value).model_dump(mode="json")

    @app.get("/api/contacts/resolve")
    async def resolve_contact(
        q: str = Query(min_length=1, max_length=2_000),
        destination_kind: str | None = Query(default=None, max_length=100),
    ) -> dict[str, Any]:
        return runtime.contacts.resolve(q, destination_kind=destination_kind).model_dump(
            mode="json"
        )

    @app.post("/api/communication/messages", dependencies=[Depends(require_admin)])
    async def ingest_communication(message: NormalizedMessageCreate) -> dict[str, bool]:
        return {"stored": runtime.communication.ingest(message)}

    @app.get("/api/communication/search")
    async def search_communication(
        q: str = Query(min_length=1, max_length=2_000),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json")
            for item in runtime.communication_store.search(q, limit=limit)
        ]

    @app.post(
        "/api/communication/{source}/sync",
        dependencies=[Depends(require_admin)],
    )
    async def sync_communication(
        source: CommunicationSource,
        q: str = Query(min_length=1, max_length=2_000),
        limit: int = Query(default=20, ge=1, le=50),
    ) -> dict[str, Any]:
        task = runtime.storage.create_task(
            user_id=configured.user_id,
            goal=f"Sync {source.value} messages for query",
            source=TaskChannel.WEB,
            conversation_id="pwa-primary",
            risk_level=RiskLevel.R1,
        )
        try:
            result = await runtime.communication.sync(
                source=source,
                task_id=task.task_id,
                query=q,
                limit=limit,
            )
        except Exception as exc:
            runtime.storage.update_task(
                task.task_id,
                state=TaskState.WAITING_EXTERNAL,
                error=f"{type(exc).__name__}: {exc}",
                event_type="connector_sync_failed",
            )
            raise
        runtime.storage.update_task(
            task.task_id,
            state=TaskState.COMPLETED,
            result=result,
            event_type="connector_sync_completed",
        )
        runtime.audit.record(
            task_id=task.task_id,
            actor="primary_user:web",
            action=f"communication.{source.value}.sync",
            result="ok",
            details={"stored": result["stored"], "query_recorded": False},
        )
        return result

    @app.get("/api/communication/messages/{source}/{message_id}")
    async def read_communication(source: CommunicationSource, message_id: str) -> dict[str, Any]:
        return runtime.communication_store.read(source=source, message_id=message_id).model_dump(
            mode="json"
        )

    @app.get("/api/communication/threads/{source}/{conversation_id}")
    async def read_communication_thread(
        source: CommunicationSource,
        conversation_id: str,
        thread_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json")
            for item in runtime.communication_store.thread(
                source=source,
                conversation_id=conversation_id,
                thread_id=thread_id,
                limit=limit,
            )
        ]

    @app.get("/api/connectors", dependencies=[Depends(require_admin)])
    async def connectors() -> list[dict[str, Any]]:
        return [
            {
                **item,
                "adapter_configured": CommunicationSource(item["provider"])
                in runtime.communication.adapters,
            }
            for item in runtime.communication_store.connectors()
        ]

    @app.post(
        "/api/connectors/google/oauth/start",
        dependencies=[Depends(require_passkey)],
    )
    async def start_google_oauth(request: GoogleOAuthConnectRequest) -> dict[str, Any]:
        required = {
            "browser_worker": configured.browser_worker_token,
            "client_id": configured.google_client_id_credential_id,
            "client_secret": configured.google_client_secret_credential_id,
            "refresh_target": configured.google_refresh_credential_id,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise HTTPException(
                status_code=409,
                detail=f"Google OAuth configuration is incomplete: {', '.join(missing)}",
            )
        origin = configured.webauthn_origin or f"http://127.0.0.1:{configured.port}"
        redirect_uri = f"{origin}/api/connectors/google/oauth/callback"
        task = runtime.storage.create_task(
            user_id=configured.user_id,
            goal="Authorize Google Calendar and Gmail",
            source=TaskChannel.WEB,
            conversation_id="pwa-primary",
            risk_level=RiskLevel.R1,
        )
        result = await runtime.browser.google_oauth_start(
            task_id=task.task_id,
            client_id_credential_id=configured.google_client_id_credential_id,
            client_secret_credential_id=configured.google_client_secret_credential_id,
            refresh_credential_id=configured.google_refresh_credential_id,
            redirect_uri=redirect_uri,
            scopes=request.scopes,
            account_label=request.account_label,
        )
        runtime.storage.update_task(
            task.task_id,
            state=TaskState.WAITING_USER,
            result={"oauth": "authorization_required", "scopes": result.get("scopes", [])},
            event_type="google_oauth_authorization_required",
        )
        return {**result, "task_id": task.task_id, "redirect_uri": redirect_uri}

    @app.get(
        "/api/connectors/google/oauth/callback",
        response_class=HTMLResponse,
        dependencies=[Depends(require_passkey)],
    )
    async def finish_google_oauth(
        code: str = Query(min_length=1, max_length=8_000),
        state: str = Query(min_length=32, max_length=512),
    ) -> HTMLResponse:
        result = await runtime.browser.google_oauth_exchange(state=state, code=code)
        task_id = str(result.get("task_id") or "")
        if task_id:
            runtime.storage.update_task(
                task_id,
                state=TaskState.COMPLETED,
                result={
                    "provider": "google",
                    "connected": True,
                    "scopes": result.get("scopes", []),
                    "refresh_token_exposed": False,
                },
                event_type="google_oauth_connected",
            )
        return HTMLResponse(
            "<!doctype html><html lang='ja'><meta charset='utf-8'>"
            "<title>Google connected</title><body><h1>Google連携が完了しました</h1>"
            "<p>Refresh tokenはSecret Workerへ暗号化保存され、CoreやLLMには表示されません。"
            "このタブを閉じてPersonal Agentへ戻れます。</p></body></html>"
        )

    @app.post(
        "/api/communication/gmail/attachments/download",
        dependencies=[Depends(require_admin)],
    )
    async def download_gmail_attachment(
        request: GmailAttachmentDownloadRequest,
    ) -> dict[str, Any]:
        refs = {
            "refresh": configured.google_refresh_credential_id,
            "client_id": configured.google_client_id_credential_id,
            "client_secret": configured.google_client_secret_credential_id,
        }
        missing = [name for name, value in refs.items() if not value]
        if missing:
            raise HTTPException(
                status_code=409,
                detail=f"Google OAuth configuration is incomplete: {', '.join(missing)}",
            )
        task = runtime.storage.create_task(
            user_id=configured.user_id,
            goal=f"Quarantine Gmail attachment {request.filename}",
            source=TaskChannel.WEB,
            conversation_id="pwa-primary",
            risk_level=RiskLevel.R1,
        )
        result = await runtime.browser.gmail_attachment(
            refresh_credential_id=refs["refresh"],
            client_id_credential_id=refs["client_id"],
            client_secret_credential_id=refs["client_secret"],
            task_id=task.task_id,
            message_id=request.message_id,
            attachment_id=request.attachment_id,
            filename=request.filename,
            media_type=request.media_type,
        )
        runtime.storage.update_task(
            task.task_id,
            state=TaskState.COMPLETED,
            result=result,
            event_type="gmail_attachment_quarantined",
        )
        return {**result, "task_id": task.task_id}

    @app.put("/api/connectors/{provider}", dependencies=[Depends(require_admin)])
    async def update_connector(
        provider: CommunicationSource, update: ConnectorUpdate
    ) -> dict[str, Any]:
        adapter = runtime.communication.adapters.get(provider)
        if update.enabled and adapter is None:
            raise HTTPException(status_code=409, detail="Adapter is not configured")
        if update.enabled and isinstance(adapter, WorkerCommunicationAdapter):
            try:
                metadata = await runtime.browser.secret_metadata()
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="Cannot verify the connector credential with Browser Worker",
                ) from exc
            credential = next(
                (item for item in metadata if item.get("credential_id") == adapter.credential_id),
                None,
            )
            if not credential or not credential.get("enabled"):
                raise HTTPException(
                    status_code=409,
                    detail="Connector credential must be re-registered before enabling",
                )
        runtime.communication_store.configure_connector(
            provider, enabled=update.enabled, scopes=update.scopes
        )
        credential_disabled: bool | None = None
        credential_disable_warning: str | None = None
        if not update.enabled and isinstance(adapter, WorkerCommunicationAdapter):
            try:
                await runtime.browser.disable_secret(adapter.credential_id)
                credential_disabled = True
            except Exception as exc:
                credential_disabled = False
                credential_disable_warning = type(exc).__name__
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="connector.update",
            result="active" if update.enabled else "revoked",
            details={
                "provider": provider.value,
                "scopes": update.scopes,
                "credential_disabled": credential_disabled,
                "credential_disable_warning": credential_disable_warning,
            },
        )
        return {
            **runtime.communication_store.connector(provider),
            "adapter_configured": adapter is not None,
            "credential_disabled": credential_disabled,
            "credential_disable_warning": credential_disable_warning,
        }

    @app.get("/api/tasks/{task_id}")
    async def task_detail(task_id: str) -> dict[str, Any]:
        return {
            "task": runtime.storage.get_task(task_id).model_dump(mode="json"),
            "steps": [step.model_dump(mode="json") for step in runtime.execution.steps(task_id)],
            "events": [
                event.model_dump(mode="json") for event in runtime.storage.list_task_events(task_id)
            ],
            "messages": runtime.storage.get_task_messages(task_id),
        }

    @app.post("/api/tasks/{task_id}/pause")
    async def pause_task(task_id: str) -> dict[str, Any]:
        return runtime.service.pause_task(task_id).model_dump(mode="json")

    @app.post("/api/tasks/{task_id}/resume", response_model=MessageResponse)
    async def resume_task(task_id: str) -> MessageResponse:
        return await runtime.service.resume_task(task_id)

    @app.post("/api/tasks/{task_id}/cancel")
    async def cancel_task(task_id: str) -> dict[str, Any]:
        return runtime.service.cancel_task(task_id).model_dump(mode="json")

    @app.get("/api/scheduler/jobs")
    async def scheduled_jobs() -> list[dict[str, Any]]:
        return runtime.storage.list_scheduled_jobs()

    @app.get("/api/calendar/events")
    async def calendar_events(
        start_at: datetime,
        end_at: datetime,
        q: str | None = Query(default=None, max_length=2_000),
    ) -> list[dict[str, Any]]:
        return [
            item.model_dump(mode="json")
            for item in runtime.calendar.search(
                query=q, start_at=start_at, end_at=end_at, limit=500
            )
        ]

    @app.get("/api/calendar/free-busy")
    async def calendar_free_busy(start_at: datetime, end_at: datetime) -> dict[str, Any]:
        return runtime.calendar.free_busy(start_at=start_at, end_at=end_at)

    @app.post("/api/calendar/events", dependencies=[Depends(require_admin)])
    async def create_calendar_event(event: CalendarEventCreate) -> dict[str, Any]:
        return runtime.calendar.create(event).model_dump(mode="json")

    @app.patch("/api/calendar/events/{event_id}", dependencies=[Depends(require_admin)])
    async def update_calendar_event(event_id: str, update: CalendarEventUpdate) -> dict[str, Any]:
        return runtime.calendar.update(event_id, update).model_dump(mode="json")

    @app.delete("/api/calendar/events/{event_id}", dependencies=[Depends(require_admin)])
    async def cancel_calendar_event(event_id: str) -> dict[str, Any]:
        return runtime.calendar.cancel(event_id).model_dump(mode="json")

    @app.get("/api/calendar/providers")
    async def calendar_providers() -> list[dict[str, Any]]:
        return runtime.calendar_sync.status()

    @app.post("/api/calendar/sync", dependencies=[Depends(require_admin)])
    async def sync_calendar(request: CalendarSyncRequest) -> dict[str, Any]:
        task = runtime.storage.create_task(
            user_id=configured.user_id,
            goal=f"Sync {request.provider} calendar",
            source=TaskChannel.WEB,
            conversation_id="pwa-primary",
            risk_level=RiskLevel.R1,
        )
        try:
            result = await runtime.calendar_sync.sync(request.provider, task_id=task.task_id)
        except Exception as exc:
            runtime.storage.update_task(
                task.task_id,
                state=TaskState.WAITING_EXTERNAL,
                error=f"{type(exc).__name__}: {exc}",
                event_type="calendar_sync_failed",
            )
            raise
        runtime.storage.update_task(
            task.task_id,
            state=TaskState.COMPLETED,
            result=result,
            event_type="calendar_sync_completed",
        )
        return result

    @app.get("/api/economic/intents", dependencies=[Depends(require_admin)])
    async def economic_intents(
        limit: int = Query(default=200, ge=1, le=1_000),
    ) -> list[dict[str, Any]]:
        return runtime.economic.list_intents(limit=limit)

    @app.get("/api/economic/transactions", dependencies=[Depends(require_admin)])
    async def economic_transactions(
        limit: int = Query(default=200, ge=1, le=1_000),
    ) -> list[dict[str, Any]]:
        return runtime.economic.list_transactions(limit=limit)

    @app.get("/api/economic/budgets", dependencies=[Depends(require_admin)])
    async def economic_budgets() -> list[dict[str, Any]]:
        return runtime.economic.list_budgets()

    @app.get("/api/money/payees", dependencies=[Depends(require_admin)])
    async def money_payees() -> list[dict[str, Any]]:
        return runtime.economic.list_payees()

    @app.get("/api/money/sandbox-accounts", dependencies=[Depends(require_admin)])
    async def sandbox_accounts() -> list[dict[str, Any]]:
        return runtime.economic.sandbox_accounts()

    @app.get("/api/files/status", dependencies=[Depends(require_admin)])
    async def files_status() -> dict[str, Any]:
        return {
            "configured": bool(runtime.files.roots),
            "roots": [str(root) for root in runtime.files.roots],
            "trash_root": str(runtime.files.trash_root),
        }

    @app.get("/api/files/recent", dependencies=[Depends(require_admin)])
    async def recent_files(
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, object]]:
        return runtime.files.recent(limit=limit)

    @app.get("/api/files/search", dependencies=[Depends(require_admin)])
    async def search_files(
        q: str = Query(min_length=1, max_length=2_000),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, object]]:
        return runtime.files.search(q, limit=limit)

    @app.post("/api/files/inspect", dependencies=[Depends(require_admin)])
    async def inspect_file(request: FilePathRequest) -> dict[str, object]:
        return runtime.files.inspect(request.path)

    @app.post("/api/files/extract-text", dependencies=[Depends(require_admin)])
    async def extract_file_text(request: FilePathRequest) -> dict[str, object]:
        return runtime.files.extract_text(request.path, pages=request.pages)

    @app.get("/api/home/status", dependencies=[Depends(require_admin)])
    async def home_status() -> dict[str, Any]:
        return {
            "configured": bool(configured.home_assistant_url and configured.home_assistant_token),
            "base_url": configured.home_assistant_url or None,
            "token_present": bool(configured.home_assistant_token),
            "safe_scenes": sorted(configured.home_assistant_safe_scenes),
        }

    @app.get("/api/proactive/settings")
    async def proactive_settings() -> dict[str, Any]:
        return runtime.proactive.settings()

    @app.put("/api/proactive/settings", dependencies=[Depends(require_admin)])
    async def update_proactive_settings(
        update: ProactiveSettingsUpdate,
    ) -> dict[str, Any]:
        result = runtime.proactive.update_settings(
            enabled=update.enabled,
            categories=update.categories,
            quiet_hours=update.quiet_hours,
            frequency_minutes=update.frequency_minutes,
        )
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="proactive.settings",
            result="ok",
            details=result,
        )
        return result

    @app.post("/api/proactive/scan", dependencies=[Depends(require_admin)])
    async def scan_proactive() -> dict[str, Any]:
        opportunities = runtime.proactive.scan()
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="proactive.scan",
            result="ok",
            details={"created": len(opportunities)},
        )
        return {"created": opportunities}

    @app.get("/api/proactive/briefing")
    async def proactive_briefing(
        period: str = Query(default="morning", pattern="^(morning|evening)$"),
    ) -> dict[str, Any]:
        return runtime.proactive.briefing(period=period)

    @app.get("/api/opportunities")
    async def opportunities(
        opportunity_state: str | None = Query(default=None, alias="state"),
        limit: int = Query(default=200, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        return runtime.proactive.list(state=opportunity_state, limit=limit)

    @app.post(
        "/api/opportunities/{opportunity_id}/resolve",
        dependencies=[Depends(require_admin)],
    )
    async def resolve_opportunity(opportunity_id: str) -> dict[str, Any]:
        result = runtime.proactive.resolve(opportunity_id)
        runtime.audit.record(
            task_id=result.get("notified_task_id"),
            actor="primary_user:web",
            action="proactive.resolve",
            result="ok",
            details={"opportunity_id": opportunity_id},
        )
        return result

    @app.get("/api/learning/preferences", dependencies=[Depends(require_admin)])
    async def preference_candidates(
        candidate_state: str | None = Query(default=None, alias="state"),
    ) -> list[dict[str, Any]]:
        return runtime.learning.list_preferences(state=candidate_state)

    @app.post(
        "/api/learning/preferences/{candidate_id}/decision",
        dependencies=[Depends(require_admin)],
    )
    async def decide_preference_candidate(
        candidate_id: str, request: LearningDecisionRequest
    ) -> dict[str, Any]:
        result = runtime.learning.decide_preference(candidate_id, accepted=request.accepted)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="learning.preference.decide",
            result=result["state"],
            details={"candidate_id": candidate_id},
        )
        return result

    @app.get("/api/learning/workflows", dependencies=[Depends(require_admin)])
    async def workflow_candidates() -> list[dict[str, Any]]:
        return runtime.learning.list_workflows()

    @app.post(
        "/api/learning/workflows/{workflow_id}/decision",
        dependencies=[Depends(require_admin)],
    )
    async def decide_workflow_candidate(
        workflow_id: str, request: LearningDecisionRequest
    ) -> dict[str, Any]:
        result = runtime.learning.decide_workflow(workflow_id, accepted=request.accepted)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="learning.workflow.decide",
            result=result["state"],
            details={
                "workflow_id": workflow_id,
                "auto_execution_enabled": False,
            },
        )
        return result

    async def finalize_approval(
        approval: dict[str, Any], *, approved: bool, auth_strength: str
    ) -> dict[str, Any]:
        runtime.audit.record(
            task_id=approval["task_id"],
            actor=(
                "primary_user:passkey" if auth_strength == "webauthn_uv" else "primary_user:web"
            ),
            action="approval.decide",
            result=approval["state"],
            details={
                "approval_id": approval["approval_id"],
                "tool": approval["tool_name"],
                "risk_level": approval["risk_level"],
                "auth_strength": auth_strength,
            },
        )
        task = runtime.storage.get_task(approval["task_id"])
        task_response: dict[str, Any] | None = None
        if approved and task.state is TaskState.WAITING_APPROVAL:
            resumed = await runtime.service.resume_task(task.task_id)
            task_response = resumed.model_dump(mode="json")
        elif not approved and task.state not in {
            TaskState.COMPLETED,
            TaskState.CANCELLED,
        }:
            runtime.service.cancel_task(task.task_id)
        return {"approval": approval, "task_response": task_response}

    @app.get("/api/webauthn/status")
    async def webauthn_status(request: Request) -> dict[str, Any]:
        return runtime.strong_auth.status(request.cookies.get(runtime.strong_auth.cookie_name))

    @app.post(
        "/api/webauthn/register/options",
        dependencies=[Depends(require_enrollment_authority)],
    )
    async def webauthn_registration_options(
        request: PasskeyRegistrationRequest,
    ) -> dict[str, Any]:
        return runtime.strong_auth.registration_options(request.label)

    @app.post(
        "/api/webauthn/register/verify",
        dependencies=[Depends(require_enrollment_authority)],
    )
    async def webauthn_registration_verify(
        request: WebAuthnResponseRequest,
    ) -> dict[str, Any]:
        result = runtime.strong_auth.verify_registration(request.challenge_id, request.credential)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="webauthn.credential.register",
            result="ok",
            details={
                "credential_id": result["credential_id"],
                "label": result["label"],
                "user_verified": result["user_verified"],
                "public_key_only": True,
            },
        )
        return result

    @app.get("/api/webauthn/credentials", dependencies=[Depends(require_admin)])
    async def webauthn_credentials() -> list[dict[str, Any]]:
        return runtime.strong_auth.list_credentials()

    @app.delete(
        "/api/webauthn/credentials/{credential_id}",
        dependencies=[Depends(require_passkey)],
    )
    async def revoke_webauthn_credential(credential_id: str) -> dict[str, Any]:
        result = runtime.strong_auth.revoke_credential(credential_id)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:passkey",
            action="webauthn.credential.revoke",
            result="ok",
            details={"credential_id": credential_id},
        )
        return result

    @app.post("/api/webauthn/login/options")
    async def webauthn_login_options() -> dict[str, Any]:
        return runtime.strong_auth.login_options()

    @app.post("/api/webauthn/login/verify")
    async def webauthn_login_verify(
        request: WebAuthnResponseRequest, response: Response
    ) -> dict[str, Any]:
        outcome = runtime.strong_auth.verify_authentication(
            request.challenge_id, request.credential
        )
        if outcome.purpose != "login" or not outcome.session_token:
            raise StrongAuthRejected("WebAuthn challenge is not a login challenge")
        response.set_cookie(
            key=runtime.strong_auth.cookie_name,
            value=outcome.session_token,
            max_age=configured.webauthn_session_ttl_hours * 3600,
            secure=runtime.strong_auth.secure_cookie,
            httponly=True,
            samesite="strict",
            path="/",
        )
        runtime.audit.record(
            task_id=None,
            actor="primary_user:passkey",
            action="webauthn.session.create",
            result="ok",
            details={
                "credential_id": outcome.credential_id,
                "expires_at": outcome.session_expires_at,
                "user_verified": True,
            },
        )
        return {
            "authenticated": True,
            "credential_id": outcome.credential_id,
            "expires_at": outcome.session_expires_at,
        }

    @app.post("/api/webauthn/logout")
    async def webauthn_logout(request: Request, response: Response) -> dict[str, bool]:
        revoked = runtime.strong_auth.logout(request.cookies.get(runtime.strong_auth.cookie_name))
        response.delete_cookie(
            runtime.strong_auth.cookie_name,
            path="/",
            secure=runtime.strong_auth.secure_cookie,
            httponly=True,
            samesite="strict",
        )
        return {"logged_out": revoked}

    @app.post(
        "/api/approvals/{approval_id}/webauthn/options",
        dependencies=[Depends(require_admin)],
    )
    async def approval_webauthn_options(approval_id: str) -> dict[str, Any]:
        return runtime.strong_auth.approval_options(approval_id)

    @app.post(
        "/api/approvals/{approval_id}/webauthn/verify",
        dependencies=[Depends(require_admin)],
    )
    async def approval_webauthn_verify(
        approval_id: str, request: WebAuthnResponseRequest
    ) -> dict[str, Any]:
        outcome = runtime.strong_auth.verify_authentication(
            request.challenge_id, request.credential
        )
        if (
            outcome.purpose != "approval"
            or outcome.approval is None
            or outcome.approval["approval_id"] != approval_id
        ):
            raise StrongAuthRejected("WebAuthn challenge is not bound to this approval")
        return await finalize_approval(
            outcome.approval,
            approved=True,
            auth_strength="webauthn_uv",
        )

    @app.get("/api/approvals", dependencies=[Depends(require_admin)])
    async def approvals(
        approval_state: str | None = Query(default=None, alias="state"),
        limit: int = Query(default=200, ge=1, le=1_000),
    ) -> list[dict[str, Any]]:
        if approval_state not in {None, "pending", "approved", "denied", "consumed"}:
            raise HTTPException(status_code=400, detail="Invalid approval state")
        return runtime.storage.list_approvals(state=approval_state, limit=limit)

    @app.post("/api/approvals/{approval_id}/decision", dependencies=[Depends(require_admin)])
    async def decide_approval(approval_id: str, request: ApprovalDecisionRequest) -> dict[str, Any]:
        try:
            approval = runtime.storage.decide_approval(
                approval_id,
                approved=request.approved,
                actor="primary_user:web",
                method="admin_token",
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return await finalize_approval(
            approval,
            approved=request.approved,
            auth_strength="admin_token",
        )

    @app.get("/api/auth/sessions", dependencies=[Depends(require_admin)])
    async def auth_sessions() -> list[dict[str, Any]]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        return await runtime.browser.auth_sessions()

    @app.post("/api/auth/{profile}/otp", dependencies=[Depends(require_admin)])
    async def submit_auth_otp(profile: BrowserProfile, request: OtpSubmitRequest) -> dict[str, Any]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        code = request.code.get_secret_value()
        try:
            result = await runtime.browser.submit_auth_otp(
                profile=profile,
                auth_session_id=request.auth_session_id,
                code=code,
            )
        finally:
            code = ""
        runtime.audit.record(
            task_id=result.get("task_id"),
            actor="primary_user:web",
            action="auth.otp.submit",
            result=result.get("status", "unknown"),
            details={
                "auth_session_id": request.auth_session_id,
                "profile": profile.value,
                "otp_value_recorded": False,
            },
        )
        task_response: dict[str, Any] | None = None
        if result.get("status") == "authenticated" and result.get("task_id"):
            task = runtime.storage.get_task(result["task_id"])
            if task.state is TaskState.WAITING_AUTH:
                resumed = await runtime.service.resume_task(task.task_id)
                task_response = resumed.model_dump(mode="json")
        return {"auth": result, "task_response": task_response}

    @app.get("/api/secrets", dependencies=[Depends(require_admin)])
    async def secret_metadata() -> list[dict[str, Any]]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        return await runtime.browser.secret_metadata()

    @app.post("/api/secrets", dependencies=[Depends(require_passkey)])
    async def put_secret(request: SecretPutRequest) -> dict[str, Any]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        result = await runtime.browser.put_secret(request)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:passkey",
            action="secret.put",
            result="ok",
            details={
                "credential_id": result.get("credential_id"),
                "kind": result.get("kind"),
                "allowed_origins": result.get("allowed_origins", []),
                "secret_value_recorded": False,
            },
        )
        return result

    @app.get("/api/secrets/usage", dependencies=[Depends(require_admin)])
    async def secret_usage() -> list[dict[str, Any]]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        return await runtime.browser.secret_usage()

    @app.delete("/api/secrets/{credential_id:path}", dependencies=[Depends(require_admin)])
    async def disable_secret(credential_id: str) -> dict[str, Any]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        normalized = (
            credential_id if credential_id.startswith("secret://") else f"secret://{credential_id}"
        )
        result = await runtime.browser.disable_secret(normalized)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="secret.disable",
            result="ok",
            details={"credential_id": normalized, "secret_value_recorded": False},
        )
        return result

    @app.post("/api/notifications/claim")
    async def claim_notification(request: NotificationRequest) -> dict[str, Any] | None:
        return runtime.storage.claim_notification(
            source=request.source, conversation_id=request.conversation_id
        )

    @app.post("/api/notifications/{notification_id}/ack")
    async def acknowledge_notification(notification_id: str) -> dict[str, str]:
        runtime.storage.acknowledge_notification(notification_id)
        return {"status": "delivered"}

    @app.post("/api/notifications/{notification_id}/release")
    async def release_notification(notification_id: str) -> dict[str, str]:
        runtime.storage.release_notification(notification_id)
        return {"status": "pending"}

    @app.get("/api/system/locks")
    async def locks() -> dict[str, Any]:
        snapshot = runtime.storage.settings_snapshot()
        return {
            key: value
            for key, value in snapshot.items()
            if key in {"global_pause", "finance_lock", "browser_lock", "secret_lock"}
        }

    @app.get("/api/browser/profiles", dependencies=[Depends(require_admin)])
    async def browser_profiles() -> list[dict[str, Any]]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        return await runtime.browser.profiles()

    @app.delete("/api/browser/profiles/{profile}", dependencies=[Depends(require_admin)])
    async def close_browser_profile(profile: BrowserProfile) -> dict[str, Any]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        result = await runtime.browser.close_profile(profile)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action="browser.profile.close",
            result="ok",
            details={"profile": profile.value},
        )
        return result

    @app.get("/api/browser/takeover/{profile}", dependencies=[Depends(require_admin)])
    async def browser_takeover_status(profile: BrowserProfile) -> dict[str, Any]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        return await runtime.browser.takeover_status(profile)

    @app.post(
        "/api/browser/takeover/{profile}/release",
        dependencies=[Depends(require_admin)],
    )
    async def release_browser_takeover(
        profile: BrowserProfile, request: TakeoverReleaseRequest
    ) -> dict[str, Any]:
        if not configured.browser_worker_token:
            raise HTTPException(status_code=503, detail="Browser Worker token is not configured")
        result = await runtime.browser.release_takeover(profile, outcome=request.outcome)
        runtime.audit.record(
            task_id=result.get("task_id"),
            actor="primary_user:web",
            action="human_takeover.release",
            result=request.outcome,
            details={"profile": profile.value, "input_values_recorded": False},
        )
        return result

    @app.put("/api/system/locks/{lock_name}", dependencies=[Depends(require_admin)])
    async def update_lock(lock_name: str, update: LockUpdate) -> dict[str, Any]:
        allowed = {"global_pause", "finance_lock", "browser_lock", "secret_lock"}
        if lock_name not in allowed:
            raise HTTPException(status_code=404, detail="Unknown lock")
        policy_version = runtime.storage.set_safety_lock(lock_name, update.enabled)
        runtime.audit.record(
            task_id=None,
            actor="primary_user:web",
            action=f"system.{lock_name}.set",
            result="ok",
            details={
                "enabled": update.enabled,
                "auth_strength": "admin_token",
                "policy_version": policy_version,
            },
        )
        return {
            "lock": lock_name,
            "enabled": update.enabled,
            "policy_version": policy_version,
        }

    @app.get("/api/audit", dependencies=[Depends(require_admin)])
    async def audit(
        q: str | None = Query(default=None, max_length=2_000),
        limit: int = Query(200, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        return runtime.storage.list_audit(query=q, limit=limit)

    static_dir = Path(__file__).parent / "static"
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="ui")
    return app
