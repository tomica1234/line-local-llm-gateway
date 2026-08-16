from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Annotated, Protocol

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, status

from .config import LineDesktopBridgeSettings
from .models import SendRequest, SendResponse, SnapshotResponse
from .store import LineDesktopBridgeStore


class LineDesktopBackend(Protocol):
    async def snapshot(self) -> SnapshotResponse: ...

    async def send(self, request: SendRequest) -> SendResponse: ...


def create_line_desktop_bridge_app(
    settings: LineDesktopBridgeSettings,
    backend: LineDesktopBackend | None = None,
) -> FastAPI:
    settings.validate()
    store = LineDesktopBridgeStore(settings.database_path)
    store.initialize()
    if backend is None:
        from .windows_backend import WindowsLineDesktopBackend

        backend = WindowsLineDesktopBackend(settings, store)

    push_status: dict[str, object] = {
        "configured": bool(settings.core_ingest_url),
        "last_push_at": None,
        "last_error": None,
        "received": 0,
        "stored": 0,
    }

    async def push_snapshot_once() -> dict[str, object]:
        if not settings.core_ingest_url:
            raise RuntimeError("Core ingest is not configured")
        snapshot = await backend.snapshot()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                settings.core_ingest_url,
                headers={"X-Line-Desktop-Token": settings.token},
                json=snapshot.model_dump(mode="json"),
            )
            response.raise_for_status()
            result = response.json()
        push_status.update(
            {
                "last_push_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "last_error": None,
                "received": int(result.get("received", 0)),
                "stored": int(result.get("stored", 0)),
            }
        )
        return result

    async def sync_loop() -> None:
        while True:
            try:
                await push_snapshot_once()
            except Exception as exc:
                push_status["last_error"] = type(exc).__name__
            await asyncio.sleep(settings.sync_interval_seconds)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        task = None
        if settings.core_ingest_url:
            task = asyncio.create_task(sync_loop())
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    def require_token(
        x_line_desktop_token: Annotated[str | None, Header()] = None,
    ) -> None:
        if not x_line_desktop_token or not secrets.compare_digest(
            x_line_desktop_token, settings.token
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid LINE Desktop Bridge token",
            )

    app = FastAPI(
        title="Personal Agent LINE Desktop Bridge",
        version="0.1.0",
        description="Loopback-only OCR bridge for the logged-in Windows LINE client.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.backend = backend
    app.state.store = store

    @app.get("/v1/health", dependencies=[Depends(require_token)])
    async def health() -> dict[str, object]:
        line_running = False
        session_state = "not_running"
        if hasattr(backend, "_line_windows"):
            line_running = bool(backend._line_windows())  # type: ignore[attr-defined]
        if line_running and hasattr(backend, "session_state"):
            try:
                session_state = str(backend.session_state())  # type: ignore[attr-defined]
            except Exception:
                session_state = "unknown"
        return {
            "status": "ok",
            "line_running": line_running,
            "session_state": session_state,
            "capture_mode": "memory_only_windows_ocr",
            "screenshots_persisted": False,
            "send_enabled": settings.send_enabled,
            "send_allowlist_count": len(settings.send_allowlist),
            "core_push": dict(push_status),
        }

    @app.post(
        "/v1/snapshot",
        response_model=SnapshotResponse,
        dependencies=[Depends(require_token)],
    )
    async def snapshot() -> SnapshotResponse:
        return await backend.snapshot()

    @app.post("/v1/sync", dependencies=[Depends(require_token)])
    async def sync_now() -> dict[str, object]:
        return await push_snapshot_once()

    @app.post(
        "/v1/send",
        response_model=SendResponse,
        dependencies=[Depends(require_token)],
    )
    async def send(request: SendRequest) -> SendResponse:
        return await backend.send(request)

    return app
