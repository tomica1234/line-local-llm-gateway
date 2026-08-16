from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .storage import Storage
from .types import Channel, RiskLevel, TaskState


def _directory_size(root: Path) -> int:
    if not root.exists():
        return 0
    if root.is_file():
        return root.stat().st_size
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def _process_memory_bytes() -> int | None:
    if sys.platform.startswith("linux"):
        try:
            resident_pages = int(Path("/proc/self/statm").read_text().split()[1])
            return resident_pages * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError, IndexError):
            return None
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb
            ):
                return int(counters.WorkingSetSize)
        except (AttributeError, OSError):
            return None
    return None


def _gpu_snapshot() -> list[dict[str, object]]:
    executable = shutil.which("nvidia-smi")
    if not executable:
        return []
    try:
        result = subprocess.run(
            [
                executable,
                "--query-gpu=name,utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    devices: list[dict[str, object]] = []
    for line in result.stdout.splitlines():
        fields = [value.strip() for value in line.split(",")]
        if len(fields) != 4:
            continue
        try:
            devices.append(
                {
                    "name": fields[0],
                    "utilization_percent": float(fields[1]),
                    "memory_used_mib": float(fields[2]),
                    "memory_total_mib": float(fields[3]),
                }
            )
        except ValueError:
            continue
    return devices


class ObservabilityService:
    def __init__(
        self,
        storage: Storage,
        *,
        trash_root: Path,
        database_quota_bytes: int,
        trash_quota_bytes: int,
    ) -> None:
        self.storage = storage
        self.trash_root = trash_root
        self.database_quota_bytes = database_quota_bytes
        self.trash_quota_bytes = trash_quota_bytes
        self.started_at = time.time()

    def health(self) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            task_rows = connection.execute(
                "SELECT state, COUNT(*) AS count FROM tasks GROUP BY state"
            ).fetchall()
        database_bytes = _directory_size(self.storage.path)
        trash_bytes = _directory_size(self.trash_root)
        disk = shutil.disk_usage(self.storage.path.parent.resolve())
        load_average = list(os.getloadavg()) if hasattr(os, "getloadavg") else None
        warnings = []
        if database_bytes >= self.database_quota_bytes * 0.8:
            warnings.append("DATABASE_QUOTA_80_PERCENT")
        if trash_bytes >= self.trash_quota_bytes * 0.8:
            warnings.append("TRASH_QUOTA_80_PERCENT")
        return {
            "status": "ok" if integrity == "ok" else "degraded",
            "database": {
                "integrity": integrity,
                "bytes": database_bytes,
                "quota_bytes": self.database_quota_bytes,
            },
            "trash": {
                "bytes": trash_bytes,
                "quota_bytes": self.trash_quota_bytes,
            },
            "disk": {
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
            },
            "process": {
                "pid": os.getpid(),
                "uptime_seconds": round(time.time() - self.started_at, 3),
                "resident_memory_bytes": _process_memory_bytes(),
                "load_average": load_average,
            },
            "gpu": _gpu_snapshot(),
            "tasks_by_state": {row["state"]: row["count"] for row in task_rows},
            "warnings": warnings,
        }

    def metrics(self) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            tasks = connection.execute(
                "SELECT state, route, created_at, updated_at, error, result_json FROM tasks"
            ).fetchall()
            actions = connection.execute(
                "SELECT tool_name, status, created_at, updated_at FROM actions"
            ).fetchall()
            audits = connection.execute(
                "SELECT action, result, details_json FROM audit_events"
            ).fetchall()
            approval_rows = connection.execute(
                "SELECT state, COUNT(*) AS count FROM approvals GROUP BY state"
            ).fetchall()

        task_states = Counter(row["state"] for row in tasks)
        routes = Counter(row["route"] or "unrouted" for row in tasks)
        tool_calls = Counter(row["tool_name"] for row in actions)
        tool_status = Counter(row["status"] for row in actions)
        task_durations = [self._duration_ms(row["created_at"], row["updated_at"]) for row in tasks]
        action_durations = [
            self._duration_ms(row["created_at"], row["updated_at"]) for row in actions
        ]
        model_turns: list[dict[str, object]] = []
        failure_classes: Counter[str] = Counter()
        for row in tasks:
            if row["error"]:
                failure_classes[self._failure_class(str(row["error"]))] += 1
            if not row["result_json"]:
                continue
            try:
                result = json.loads(row["result_json"])
                metrics = result.get("evidence", {}).get("model_metrics", [])
                model_turns.extend(item for item in metrics if isinstance(item, dict))
            except (json.JSONDecodeError, AttributeError):
                continue
        policy_denials = 0
        takeover_count = 0
        tool_recorded_durations: list[float] = []
        for row in audits:
            try:
                details = json.loads(row["details_json"])
            except json.JSONDecodeError:
                details = {}
            if row["result"] == "denied" or details.get("reason_code") == "POLICY_DENIED":
                policy_denials += 1
            if "takeover" in str(row["action"]).lower():
                takeover_count += 1
            if isinstance(details.get("duration_ms"), (int, float)):
                tool_recorded_durations.append(float(details["duration_ms"]))
        completion_tokens = sum(int(item.get("completion_tokens") or 0) for item in model_turns)
        model_duration_ms = sum(float(item.get("duration_ms") or 0) for item in model_turns)
        return {
            "tasks": {
                "total": len(tasks),
                "by_state": dict(task_states),
                "by_route": dict(routes),
                "duration_ms": self._distribution(task_durations),
            },
            "tools": {
                "total": len(actions),
                "by_name": dict(tool_calls),
                "by_status": dict(tool_status),
                "duration_ms": self._distribution(tool_recorded_durations or action_durations),
            },
            "model": {
                "turns": len(model_turns),
                "completion_tokens": completion_tokens,
                "duration_ms": round(model_duration_ms, 2),
                "tokens_per_second": (
                    round(completion_tokens / (model_duration_ms / 1_000), 2)
                    if model_duration_ms > 0
                    else None
                ),
                "turn_metrics": model_turns[-100:],
            },
            "safety": {
                "policy_denials": policy_denials,
                "human_takeovers": takeover_count,
                "approvals": {row["state"]: row["count"] for row in approval_rows},
            },
            "failures": dict(failure_classes),
        }

    def queue_quota_warning(self, *, user_id: str) -> str | None:
        snapshot = self.health()
        warnings = snapshot["warnings"]
        if not warnings:
            return None
        day = datetime_now_utc_date()
        try:
            last = self.storage.get_setting("last_quota_warning")
        except KeyError:
            last = None
        fingerprint = {"day": day, "warnings": warnings}
        if last == fingerprint:
            return None
        task = self.storage.create_task(
            user_id=user_id,
            goal="Storage quota warning",
            source=Channel.WEB,
            conversation_id="pwa-primary",
            risk_level=RiskLevel.R0,
        )
        self.storage.update_task(
            task.task_id,
            state=TaskState.COMPLETED,
            result={"warnings": warnings},
            event_type="quota_warning_created",
        )
        self.storage.create_scheduled_job(
            task_id=task.task_id,
            kind="quota_warning",
            run_at=utc_timestamp(),
            payload={"label": f"Storage warning: {', '.join(warnings)}"},
        )
        self.storage.materialize_due_notifications()
        self.storage.set_setting("last_quota_warning", fingerprint)
        return task.task_id

    @staticmethod
    def _duration_ms(start: str, end: str) -> float:
        return max(
            0.0,
            (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() * 1_000,
        )

    @staticmethod
    def _distribution(values: list[float]) -> dict[str, float | int | None]:
        if not values:
            return {"count": 0, "average": None, "p50": None, "p95": None}
        ordered = sorted(values)

        def percentile(value: float) -> float:
            index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * value)))
            return round(ordered[index], 2)

        return {
            "count": len(ordered),
            "average": round(sum(ordered) / len(ordered), 2),
            "p50": percentile(0.5),
            "p95": percentile(0.95),
        }

    @staticmethod
    def _failure_class(error: str) -> str:
        lowered = error.lower()
        if "policy" in lowered or "permission" in lowered:
            return "policy"
        if "browser" in lowered or "playwright" in lowered:
            return "browser"
        if "tool" in lowered or "validation" in lowered:
            return "tool"
        if "memory" in lowered or "fts" in lowered:
            return "memory"
        if "model" in lowered or "qwen" in lowered or "chat-completions" in lowered:
            return "model"
        return "external"


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat()


def datetime_now_utc_date() -> str:
    return datetime.now(UTC).date().isoformat()
