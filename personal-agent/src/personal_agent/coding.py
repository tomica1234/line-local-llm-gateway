from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .approval import ApprovalMaterial
from .config import Settings
from .storage import Storage, utc_now
from .tool_broker.broker import ToolDefinition
from .types import RiskLevel, ToolResult

CODING_SCHEMA = """
CREATE TABLE IF NOT EXISTS coding_jobs (
    job_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    step_id TEXT,
    parent_job_id TEXT REFERENCES coding_jobs(job_id),
    kind TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    prompt TEXT NOT NULL,
    sandbox TEXT NOT NULL,
    status TEXT NOT NULL,
    pid INTEGER,
    session_id TEXT,
    result_json TEXT,
    job_directory TEXT NOT NULL,
    notification_sent INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_coding_jobs_status
ON coding_jobs(status, updated_at);
"""


class RepoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo_path: str = Field(min_length=1, max_length=4_096)


class CodexStartArgs(RepoArgs):
    prompt: str = Field(min_length=1, max_length=20_000)
    sandbox: Literal["read-only", "workspace-write"] = "workspace-write"


class CodexSendArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(min_length=1, max_length=128)
    prompt: str = Field(min_length=1, max_length=20_000)


class CodingJobArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(min_length=1, max_length=128)


class TestRunArgs(RepoArgs):
    suite: Literal["pytest", "ruff", "compileall"] = "pytest"


class CodingService:
    def __init__(self, storage: Storage, settings: Settings) -> None:
        self.storage = storage
        self.settings = settings
        self.roots = tuple(root.resolve() for root in settings.coding_repo_roots)
        self.data_root = settings.coding_data_root.resolve()
        with storage.transaction() as connection:
            connection.executescript(CODING_SCHEMA)
        self.refresh_jobs()

    def repo(self, value: str) -> Path:
        path = Path(value).resolve(strict=True)
        if not path.is_dir() or not any(
            path == root or path.is_relative_to(root) for root in self.roots
        ):
            raise PermissionError("Repository is outside PERSONAL_AGENT_CODING_REPO_ROOTS")
        if not (path / ".git").exists():
            raise ValueError("Coding tools require a Git repository")
        return path

    def repo_status(self, value: str) -> dict[str, Any]:
        repo = self.repo(value)
        completed = subprocess.run(
            ["git", "status", "--short", "--branch"],
            cwd=repo,
            env=self._environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            shell=False,
            check=False,
        )
        return {
            "repo_path": str(repo),
            "exit_code": completed.returncode,
            "status": (completed.stdout + completed.stderr)[:50_000],
        }

    def start(
        self,
        *,
        task_id: str,
        step_id: str | None,
        value: CodexStartArgs,
        parent_job_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        repo = self.repo(value.repo_path)
        return self._spawn(
            task_id=task_id,
            step_id=step_id,
            kind="codex_resume" if session_id else "codex",
            repo=repo,
            prompt=value.prompt,
            sandbox=value.sandbox,
            parent_job_id=parent_job_id,
            session_id=session_id,
        )

    def send(self, *, task_id: str, step_id: str | None, value: CodexSendArgs) -> dict[str, Any]:
        parent = self.job(value.job_id)
        if parent["status"] != "completed" or not parent.get("session_id"):
            raise ValueError("Codex job must complete with a session ID before resume")
        return self.start(
            task_id=task_id,
            step_id=step_id,
            value=CodexStartArgs(
                repo_path=parent["repo_path"],
                prompt=value.prompt,
                sandbox=parent["sandbox"],
            ),
            parent_job_id=value.job_id,
            session_id=parent["session_id"],
        )

    def tests(self, *, task_id: str, step_id: str | None, value: TestRunArgs) -> dict[str, Any]:
        repo = self.repo(value.repo_path)
        commands = {
            "pytest": [sys.executable, "-m", "pytest", "-q"],
            "ruff": [sys.executable, "-m", "ruff", "check", "."],
            "compileall": [sys.executable, "-m", "compileall", "-q", "src"],
        }
        return self._spawn(
            task_id=task_id,
            step_id=step_id,
            kind=f"tests:{value.suite}",
            repo=repo,
            prompt="",
            sandbox="read-only",
            command=commands[value.suite],
        )

    def job(self, job_id: str) -> dict[str, Any]:
        self.refresh_jobs(job_id=job_id)
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM coding_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        if row is None:
            raise KeyError(job_id)
        result = dict(row)
        result["result"] = json.loads(result.pop("result_json")) if result["result_json"] else None
        return result

    def cancel(self, job_id: str) -> dict[str, Any]:
        job = self.job(job_id)
        if job["status"] not in {"queued", "running"}:
            return job
        pid = job.get("pid")
        if pid:
            try:
                if os.name == "nt":
                    os.kill(int(pid), signal.SIGTERM)
                else:
                    os.killpg(int(pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE coding_jobs SET status='cancelled', completed_at=?, updated_at=? "
                "WHERE job_id=? AND status IN ('queued','running')",
                (now, now, job_id),
            )
        return self.job(job_id)

    def cancel_task(self, task_id: str) -> int:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT job_id FROM coding_jobs WHERE task_id=? AND status IN ('queued','running')",
                (task_id,),
            ).fetchall()
        for row in rows:
            self.cancel(str(row["job_id"]))
        return len(rows)

    def refresh_jobs(self, *, job_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM coding_jobs WHERE status IN ('queued','running')"
        parameters: tuple[Any, ...] = ()
        if job_id:
            query += " AND job_id=?"
            parameters = (job_id,)
        with self.storage.read_connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        changed: list[dict[str, Any]] = []
        for row in rows:
            status_file = Path(row["job_directory"]) / "status.json"
            if status_file.exists():
                try:
                    outcome = json.loads(status_file.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                status = "completed" if int(outcome.get("exit_code", 1)) == 0 else "failed"
                now = utc_now()
                with self.storage.transaction() as connection:
                    connection.execute(
                        "UPDATE coding_jobs SET status=?, session_id=COALESCE(?, session_id), "
                        "result_json=?, completed_at=?, updated_at=? WHERE job_id=?",
                        (
                            status,
                            outcome.get("session_id"),
                            json.dumps(outcome, ensure_ascii=False),
                            now,
                            now,
                            row["job_id"],
                        ),
                    )
                changed.append({"job_id": row["job_id"], "status": status, **outcome})
            elif row["pid"] and not self._pid_running(int(row["pid"])):
                now = utc_now()
                outcome = {
                    "reason_code": "CODING_PROCESS_EXITED_WITHOUT_RESULT",
                    "retry_allowed": False,
                }
                with self.storage.transaction() as connection:
                    connection.execute(
                        "UPDATE coding_jobs SET status='submitted_unknown', result_json=?, "
                        "completed_at=?, updated_at=? WHERE job_id=?",
                        (json.dumps(outcome), now, now, row["job_id"]),
                    )
                changed.append({"job_id": row["job_id"], "status": "submitted_unknown", **outcome})
        return changed

    def pending_notifications(self) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM coding_jobs WHERE status IN ('completed','failed',"
                "'submitted_unknown') AND notification_sent=0 ORDER BY completed_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def schedule_completion_notification(self, job: dict[str, Any]) -> None:
        now = utc_now()
        label = f"Coding job {job['status']}: {Path(job['repo_path']).name}"
        with self.storage.transaction() as connection:
            existing = connection.execute(
                "SELECT job_id FROM scheduled_jobs WHERE resource_type='coding_job' "
                "AND resource_id=? AND kind='coding_job_result'",
                (job["job_id"],),
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO scheduled_jobs(job_id, task_id, kind, run_at, payload_json, "
                    "resource_type, resource_id, status, created_at, updated_at) "
                    "VALUES (?, ?, 'coding_job_result', ?, ?, 'coding_job', ?, "
                    "'scheduled', ?, ?)",
                    (
                        str(uuid.uuid4()),
                        job["task_id"],
                        now,
                        json.dumps({"label": label}, ensure_ascii=False),
                        job["job_id"],
                        now,
                        now,
                    ),
                )
            connection.execute(
                "UPDATE coding_jobs SET notification_sent=1, updated_at=? WHERE job_id=?",
                (now, job["job_id"]),
            )

    def _spawn(
        self,
        *,
        task_id: str,
        step_id: str | None,
        kind: str,
        repo: Path,
        prompt: str,
        sandbox: str,
        command: list[str] | None = None,
        parent_job_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        job_directory = self.data_root / job_id
        job_directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        request_path = job_directory / "request.json"
        request_path.write_text(
            json.dumps(
                {
                    "kind": kind,
                    "repo": str(repo),
                    "prompt": prompt,
                    "sandbox": sandbox,
                    "session_id": session_id,
                    "command": command,
                    "codex_executable": self.settings.codex_executable,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        try:
            request_path.chmod(0o600)
        except OSError:
            pass
        process = subprocess.Popen(
            [sys.executable, "-m", "personal_agent.coding_runner", str(job_directory)],
            cwd=repo,
            env=self._environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
        )
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO coding_jobs(job_id, task_id, step_id, parent_job_id, kind, "
                "repo_path, prompt, sandbox, status, pid, session_id, job_directory, "
                "created_at, started_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
                "'running', ?, ?, ?, ?, ?, ?)",
                (
                    job_id,
                    task_id,
                    step_id,
                    parent_job_id,
                    kind,
                    str(repo),
                    prompt,
                    sandbox,
                    process.pid,
                    session_id,
                    str(job_directory),
                    now,
                    now,
                    now,
                ),
            )
        return {
            "job_id": job_id,
            "status": "running",
            "repo_path": str(repo),
            "sandbox": sandbox,
            "push_allowed": False,
            "retry_after_unknown": False,
        }

    @staticmethod
    def _pid_running(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = {
            "PATH",
            "HOME",
            "USERPROFILE",
            "CODEX_HOME",
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


def coding_tools(service: CodingService) -> list[ToolDefinition[Any]]:
    def approval_material(args: BaseModel) -> ApprovalMaterial:
        parsed = CodexStartArgs.model_validate(args)
        return ApprovalMaterial.create(
            action_type="coding.codex.start",
            title="Codex coding jobを開始",
            human_summary=(
                "表示されたrepository内でCodexをworkspace-write sandboxとして開始します。"
                "Commit・push・外部credential操作は許可しません。"
            ),
            structured_payload={
                "repo_path": str(service.repo(parsed.repo_path)),
                "prompt": parsed.prompt,
                "sandbox": parsed.sandbox,
                "network_access": False,
                "commit_allowed": False,
                "push_allowed": False,
            },
        )

    return [
        ToolDefinition(
            "coding.repo.status",
            "Read bounded Git status for an allowlisted repository.",
            RepoArgs,
            lambda a, _c: ToolResult(
                status="ok", evidence=service.repo_status(RepoArgs.model_validate(a).repo_path)
            ),
            RiskLevel.R0,
            required_permissions=("coding.read",),
        ),
        ToolDefinition(
            "coding.repo.open",
            "Resolve an allowlisted Git repository without changing it.",
            RepoArgs,
            lambda a, _c: ToolResult(
                status="ok",
                evidence={"repo_path": str(service.repo(RepoArgs.model_validate(a).repo_path))},
            ),
            RiskLevel.R0,
            required_permissions=("coding.read",),
        ),
        ToolDefinition(
            "coding.codex.start",
            "Start a durable sandboxed Codex coding job.",
            CodexStartArgs,
            lambda a, c: ToolResult(
                status="waiting_external",
                external_id=(
                    job := service.start(
                        task_id=c.task_id, step_id=c.step_id, value=CodexStartArgs.model_validate(a)
                    )
                )["job_id"],
                evidence={**job, "reason_code": "CODING_JOB_RUNNING"},
                next_action="coding.codex.status",
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("coding.execute",),
            approval_material_builder=approval_material,
        ),
        ToolDefinition(
            "coding.codex.send",
            "Resume a completed durable Codex session with a new prompt.",
            CodexSendArgs,
            lambda a, c: ToolResult(
                status="waiting_external",
                external_id=(
                    job := service.send(
                        task_id=c.task_id, step_id=c.step_id, value=CodexSendArgs.model_validate(a)
                    )
                )["job_id"],
                evidence={**job, "reason_code": "CODING_JOB_RUNNING"},
                next_action="coding.codex.status",
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("coding.execute",),
        ),
        ToolDefinition(
            "coding.codex.status",
            "Read a durable coding job and its bounded result.",
            CodingJobArgs,
            lambda a, _c: ToolResult(
                status="ok", evidence=service.job(CodingJobArgs.model_validate(a).job_id)
            ),
            RiskLevel.R0,
            required_permissions=("coding.read",),
        ),
        ToolDefinition(
            "coding.codex.cancel",
            "Cancel a running Codex job process group.",
            CodingJobArgs,
            lambda a, _c: ToolResult(
                status="ok", evidence=service.cancel(CodingJobArgs.model_validate(a).job_id)
            ),
            RiskLevel.R2,
            mutation=True,
            required_permissions=("coding.execute",),
        ),
        ToolDefinition(
            "coding.tests.run",
            "Run a fixed pytest, Ruff, or compileall command in a repository.",
            TestRunArgs,
            lambda a, c: ToolResult(
                status="waiting_external",
                external_id=(
                    job := service.tests(
                        task_id=c.task_id, step_id=c.step_id, value=TestRunArgs.model_validate(a)
                    )
                )["job_id"],
                evidence={**job, "reason_code": "CODING_TEST_JOB_RUNNING"},
                next_action="coding.codex.status",
            ),
            RiskLevel.R1,
            mutation=True,
            required_permissions=("coding.test",),
        ),
    ]
