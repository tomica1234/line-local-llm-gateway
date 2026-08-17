from __future__ import annotations

import ctypes
import os
import platform
import signal
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .approval import ApprovalMaterial
from .config import Settings
from .storage import Storage, utc_now
from .tool_broker.broker import ToolContext, ToolDefinition
from .types import RiskLevel, ToolResult

COMPUTER_SCHEMA = """
CREATE TABLE IF NOT EXISTS computer_jobs (
    job_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    command_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    cwd TEXT,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_computer_jobs_status
ON computer_jobs(status, updated_at);
"""


class NotificationArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=2_000)


class EmptyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProcessArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pid: int = Field(gt=0)


class AppArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._-]+$")


class JobStartArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._-]+$")
    cwd: str | None = Field(default=None, max_length=4_096)


class JobArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(min_length=1, max_length=128)


class CommandArgs(JobStartArgs):
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    max_output_chars: int = Field(default=20_000, ge=1_000, le=100_000)


class ClipboardWriteArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(max_length=20_000)


class DesktopSnapshotArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(default="desktop", max_length=100)


class DesktopClickArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    x: int = Field(ge=0, le=100_000)
    y: int = Field(ge=0, le=100_000)
    target: str = Field(min_length=1, max_length=500)


class DesktopTypeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=20_000)
    target: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def reject_secret_target(self) -> DesktopTypeArgs:
        if any(
            marker in self.target.casefold()
            for marker in ("password", "パスワード", "otp", "認証コード", "card", "cvv")
        ):
            raise ValueError("Secret desktop fields must use Secret Worker, not desktop.type")
        return self


class ComputerService:
    def __init__(self, storage: Storage, settings: Settings | None = None) -> None:
        self.storage = storage
        self.settings = settings or Settings()
        self.apps = dict(self.settings.computer_app_allowlist)
        self.commands = dict(self.settings.computer_command_allowlist)
        self.cwd_roots = tuple(
            root.resolve()
            for root in (*self.settings.files_roots, *self.settings.coding_repo_roots)
        )
        with storage.transaction() as connection:
            connection.executescript(COMPUTER_SCHEMA)

    @staticmethod
    def system_status() -> dict[str, Any]:
        return {
            "platform": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        }

    @staticmethod
    def processes() -> list[dict[str, Any]]:
        import psutil

        result = []
        for process in psutil.process_iter(["pid", "name", "status", "create_time"]):
            try:
                result.append(process.info)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            if len(result) >= 500:
                break
        return result

    @staticmethod
    def process_status(pid: int) -> dict[str, Any]:
        import psutil

        try:
            process = psutil.Process(pid)
            return {
                "pid": pid,
                "name": process.name(),
                "status": process.status(),
                "running": process.is_running(),
            }
        except psutil.NoSuchProcess:
            return {"pid": pid, "status": "not_found", "running": False}

    def stop_process(self, pid: int) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            owned = connection.execute(
                "SELECT job_id FROM computer_jobs WHERE pid=? AND status='running'", (pid,)
            ).fetchone()
        if owned is None:
            raise PermissionError("Only a process started by Personal Agent may be stopped")
        self._terminate(pid)
        self._set_job_status(str(owned["job_id"]), "cancelled")
        return {"pid": pid, "stopped": True, "owned_process": True}

    def launch(self, *, task_id: str, app_id: str) -> dict[str, Any]:
        command = self.apps.get(app_id)
        if command is None:
            raise PermissionError("Application is not in the operator allowlist")
        return self._start(task_id=task_id, kind="app", command_id=app_id, command=command)

    def start_job(self, *, task_id: str, command_id: str, cwd: str | None) -> dict[str, Any]:
        command = self.commands.get(command_id)
        if command is None:
            raise PermissionError("Command template is not in the operator allowlist")
        return self._start(
            task_id=task_id,
            kind="command",
            command_id=command_id,
            command=command,
            cwd=self._cwd(cwd),
        )

    def run_command(
        self,
        *,
        command_id: str,
        cwd: str | None,
        timeout_seconds: int,
        max_output_chars: int,
    ) -> dict[str, Any]:
        command = self.commands.get(command_id)
        if command is None:
            raise PermissionError("Command template is not in the operator allowlist")
        completed = subprocess.run(
            list(command),
            cwd=self._cwd(cwd),
            env=self._environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
        output = (completed.stdout + completed.stderr)[:max_output_chars]
        return {
            "command_id": command_id,
            "exit_code": completed.returncode,
            "output": output,
            "output_truncated": len(completed.stdout) + len(completed.stderr) > len(output),
            "shell": False,
            "environment_allowlisted": True,
        }

    def job(self, job_id: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM computer_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        if row is None:
            raise KeyError(job_id)
        result = dict(row)
        if result["status"] == "running" and not self._pid_running(int(result["pid"])):
            self._set_job_status(job_id, "exited")
            result["status"] = "exited"
        return result

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        job = self.job(job_id)
        if job["status"] != "running":
            return job
        self._terminate(int(job["pid"]))
        self._set_job_status(job_id, "cancelled")
        return self.job(job_id)

    @staticmethod
    def clipboard_read() -> dict[str, Any]:
        text = ComputerService._clipboard_get()[:20_000]
        secret_like = any(
            marker in text.casefold()
            for marker in (
                "password",
                "api_key",
                "secret://",
                "BEGIN PRIVATE KEY".casefold(),  # pragma: allowlist secret
            )
        )
        return {
            "text": "[REDACTED_SECRET_LIKE_CLIPBOARD]" if secret_like else text,
            "redacted": secret_like,
            "truncated": len(text) >= 20_000,
        }

    @staticmethod
    def clipboard_write(text: str) -> dict[str, Any]:
        ComputerService._clipboard_set(text)
        return {"written_characters": len(text), "value_recorded": False}

    def desktop_snapshot(self, label: str) -> dict[str, Any]:
        if os.name != "nt":
            raise RuntimeError("Desktop automation is only available on Windows")
        from PIL import ImageGrab

        root = self.storage.path.parent / "desktop-snapshots"
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = root / f"{uuid.uuid4()}-{label}.png"
        image = ImageGrab.grab(all_screens=True)
        image.save(path, format="PNG")
        return {"path": str(path), "width": image.width, "height": image.height}

    @staticmethod
    def desktop_click(x: int, y: int, target: str) -> dict[str, Any]:
        if os.name != "nt":
            raise RuntimeError("Desktop automation is only available on Windows")
        user32 = ctypes.windll.user32
        user32.SetCursorPos(x, y)
        user32.mouse_event(0x0002, 0, 0, 0, 0)
        user32.mouse_event(0x0004, 0, 0, 0, 0)
        return {"x": x, "y": y, "target": target, "clicked": True}

    @staticmethod
    def desktop_type(text: str, target: str) -> dict[str, Any]:
        if os.name != "nt":
            raise RuntimeError("Desktop automation is only available on Windows")
        ComputerService._clipboard_set(text)
        user32 = ctypes.windll.user32
        user32.keybd_event(0x11, 0, 0, 0)
        user32.keybd_event(0x56, 0, 0, 0)
        user32.keybd_event(0x56, 0, 0x0002, 0)
        user32.keybd_event(0x11, 0, 0x0002, 0)
        return {"target": target, "typed_characters": len(text), "value_recorded": False}

    def _start(
        self,
        *,
        task_id: str,
        kind: str,
        command_id: str,
        command: tuple[str, ...],
        cwd: Path | None = None,
    ) -> dict[str, Any]:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=self._environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
        )
        job_id = str(uuid.uuid4())
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO computer_jobs(job_id, task_id, kind, command_id, pid, cwd, "
                "status, started_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?)",
                (
                    job_id,
                    task_id,
                    kind,
                    command_id,
                    process.pid,
                    str(cwd) if cwd else None,
                    now,
                    now,
                ),
            )
        return {"job_id": job_id, "pid": process.pid, "status": "running"}

    def _cwd(self, value: str | None) -> Path | None:
        if value is None:
            return None
        path = Path(value).resolve(strict=True)
        if not path.is_dir() or not any(
            path == root or path.is_relative_to(root) for root in self.cwd_roots
        ):
            raise PermissionError("Working directory is outside configured roots")
        return path

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = {
            "PATH",
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "LANG",
            "LC_ALL",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        }
        return {key: value for key, value in os.environ.items() if key in allowed}

    @staticmethod
    def _pid_running(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    @staticmethod
    def _terminate(pid: int) -> None:
        if os.name == "nt":
            os.kill(pid, signal.SIGTERM)
        else:
            os.killpg(pid, signal.SIGTERM)

    def _set_job_status(self, job_id: str, status: str) -> None:
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE computer_jobs SET status=?, completed_at=?, updated_at=? WHERE job_id=?",
                (status, now, now, job_id),
            )

    @staticmethod
    def _clipboard_get() -> str:
        import tkinter

        root = tkinter.Tk()
        root.withdraw()
        try:
            return str(root.clipboard_get())
        finally:
            root.destroy()

    @staticmethod
    def _clipboard_set(text: str) -> None:
        import tkinter

        root = tkinter.Tk()
        root.withdraw()
        try:
            root.clipboard_clear()
            root.clipboard_append(text)
            root.update()
        finally:
            root.destroy()


def computer_tools(storage: Storage, settings: Settings | None = None) -> list[ToolDefinition[Any]]:
    service = ComputerService(storage, settings)

    def notify(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = NotificationArgs.model_validate(args)
        job_id = storage.create_scheduled_job(
            task_id=context.task_id,
            kind="local_notification",
            run_at=datetime.now(UTC).isoformat(),
            payload={"label": f"{parsed.title}: {parsed.body}"},
        )
        storage.materialize_due_notifications()
        return ToolResult(status="ok", evidence={"job_id": job_id, "delivery": "durable"})

    def approval(action: str, title: str, payload: dict[str, Any]) -> ApprovalMaterial:
        return ApprovalMaterial.create(
            action_type=action,
            title=title,
            human_summary="表示された対象に対して、型付けされたPC操作を1回だけ実行します。",
            structured_payload=payload,
        )

    definitions = [
        ToolDefinition(
            "computer.get_status",
            "Read bounded OS status.",
            EmptyArgs,
            lambda _a, _c: ToolResult(status="ok", evidence=service.system_status()),
            RiskLevel.R0,
            required_permissions=("computer.read",),
        ),
        ToolDefinition(
            "computer.process.list",
            "List bounded process metadata.",
            EmptyArgs,
            lambda _a, _c: ToolResult(status="ok", evidence={"processes": service.processes()}),
            RiskLevel.R0,
            required_permissions=("computer.read",),
        ),
        ToolDefinition(
            "computer.process.status",
            "Read one process status.",
            ProcessArgs,
            lambda a, _c: ToolResult(
                status="ok", evidence=service.process_status(ProcessArgs.model_validate(a).pid)
            ),
            RiskLevel.R0,
            required_permissions=("computer.read",),
        ),
        ToolDefinition(
            "computer.process.stop",
            "Stop only a process started by this Agent.",
            ProcessArgs,
            lambda a, _c: ToolResult(
                status="ok", evidence=service.stop_process(ProcessArgs.model_validate(a).pid)
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.process.stop",),
            approval_material_builder=lambda a: approval(
                "computer.process.stop",
                "Agent管理プロセスを停止",
                {"pid": ProcessArgs.model_validate(a).pid},
            ),
        ),
        ToolDefinition(
            "computer.app.list",
            "List operator-allowlisted applications.",
            EmptyArgs,
            lambda _a, _c: ToolResult(status="ok", evidence={"apps": sorted(service.apps)}),
            RiskLevel.R0,
            required_permissions=("computer.read",),
        ),
        ToolDefinition(
            "computer.app.launch",
            "Launch one allowlisted application.",
            AppArgs,
            lambda a, c: ToolResult(
                status="ok",
                evidence=service.launch(task_id=c.task_id, app_id=AppArgs.model_validate(a).app_id),
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.app.launch",),
            approval_material_builder=lambda a: approval(
                "computer.app.launch", "アプリを起動", {"app_id": AppArgs.model_validate(a).app_id}
            ),
        ),
        ToolDefinition(
            "computer.app.close",
            "Close only an Agent-launched application job.",
            JobArgs,
            lambda a, _c: ToolResult(
                status="ok", evidence=service.cancel_job(JobArgs.model_validate(a).job_id)
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.app.launch",),
        ),
        ToolDefinition(
            "computer.job.start",
            "Start an operator-allowlisted command as a job.",
            JobStartArgs,
            lambda a, c: ToolResult(
                status="ok",
                evidence=service.start_job(
                    task_id=c.task_id,
                    command_id=JobStartArgs.model_validate(a).command_id,
                    cwd=JobStartArgs.model_validate(a).cwd,
                ),
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.job.run",),
            approval_material_builder=lambda a: approval(
                "computer.job.start",
                "Allowlist jobを開始",
                JobStartArgs.model_validate(a).model_dump(),
            ),
        ),
        ToolDefinition(
            "computer.job.status",
            "Read an Agent job status.",
            JobArgs,
            lambda a, _c: ToolResult(
                status="ok", evidence=service.job(JobArgs.model_validate(a).job_id)
            ),
            RiskLevel.R0,
            required_permissions=("computer.read",),
        ),
        ToolDefinition(
            "computer.job.cancel",
            "Cancel an Agent-managed job and process group.",
            JobArgs,
            lambda a, _c: ToolResult(
                status="ok", evidence=service.cancel_job(JobArgs.model_validate(a).job_id)
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.job.run",),
        ),
        ToolDefinition(
            "computer.command.run",
            "Run one fixed command template without a shell.",
            CommandArgs,
            lambda a, _c: ToolResult(
                status="ok",
                evidence=service.run_command(**CommandArgs.model_validate(a).model_dump()),
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.command.run",),
            approval_material_builder=lambda a: approval(
                "computer.command.run",
                "固定コマンドを実行",
                CommandArgs.model_validate(a).model_dump(),
            ),
        ),
        ToolDefinition(
            "computer.clipboard.read",
            "Read bounded clipboard text with secret-like redaction.",
            EmptyArgs,
            lambda _a, _c: ToolResult(status="ok", evidence=service.clipboard_read()),
            RiskLevel.R1,
            required_permissions=("computer.clipboard.read",),
        ),
        ToolDefinition(
            "computer.clipboard.write",
            "Write bounded text to the clipboard.",
            ClipboardWriteArgs,
            lambda a, _c: ToolResult(
                status="ok",
                evidence=service.clipboard_write(ClipboardWriteArgs.model_validate(a).text),
            ),
            RiskLevel.R1,
            mutation=True,
            required_permissions=("computer.clipboard.write",),
        ),
        ToolDefinition(
            "computer.desktop.snapshot",
            "Capture a local desktop screenshot.",
            DesktopSnapshotArgs,
            lambda a, _c: ToolResult(
                status="ok",
                evidence=service.desktop_snapshot(DesktopSnapshotArgs.model_validate(a).label),
            ),
            RiskLevel.R1,
            required_permissions=("computer.desktop.read",),
        ),
        ToolDefinition(
            "computer.desktop.click",
            "Click audited desktop coordinates.",
            DesktopClickArgs,
            lambda a, _c: ToolResult(
                status="ok",
                evidence=service.desktop_click(**DesktopClickArgs.model_validate(a).model_dump()),
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.desktop.interact",),
            approval_material_builder=lambda a: approval(
                "computer.desktop.click",
                "デスクトップをクリック",
                DesktopClickArgs.model_validate(a).model_dump(),
            ),
        ),
        ToolDefinition(
            "computer.desktop.type",
            "Type bounded non-secret text into a described target.",
            DesktopTypeArgs,
            lambda a, _c: ToolResult(
                status="ok",
                evidence=service.desktop_type(**DesktopTypeArgs.model_validate(a).model_dump()),
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.desktop.interact",),
            approval_material_builder=lambda a: approval(
                "computer.desktop.type",
                "デスクトップへ入力",
                {
                    "target": DesktopTypeArgs.model_validate(a).target,
                    "text": DesktopTypeArgs.model_validate(a).text,
                },
            ),
        ),
        ToolDefinition(
            "computer.notify",
            "Create a durable local notification.",
            NotificationArgs,
            notify,
            RiskLevel.R1,
            mutation=True,
            required_permissions=("computer.write",),
        ),
    ]

    def lock(_args: BaseModel, _context: ToolContext) -> ToolResult:
        if os.name != "nt":
            raise RuntimeError("computer.lock is only available on Windows")
        if not ctypes.windll.user32.LockWorkStation():
            raise ctypes.WinError()
        return ToolResult(status="ok", evidence={"locked": True})

    definitions.append(
        ToolDefinition(
            "computer.lock",
            "Lock the Windows workstation.",
            EmptyArgs,
            lock,
            RiskLevel.R2,
            mutation=True,
            required_permissions=("computer.lock",),
        )
    )
    return definitions
