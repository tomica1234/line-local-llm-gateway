from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def _session_id(line: str) -> str | None:
    try:
        value = json.loads(line)
    except ValueError:
        return None
    if not isinstance(value, dict):
        return None
    for key in ("thread_id", "session_id"):
        if value.get(key):
            return str(value[key])
    item = value.get("item")
    if isinstance(item, dict):
        for key in ("thread_id", "session_id"):
            if item.get(key):
                return str(item[key])
    return None


def run(job_directory: Path) -> int:
    request = json.loads((job_directory / "request.json").read_text(encoding="utf-8"))
    repo = str(request["repo"])
    prompt = str(request.get("prompt") or "")
    command = request.get("command")
    last_message = job_directory / "last-message.txt"
    if command:
        argv = [str(item) for item in command]
    else:
        executable = str(request.get("codex_executable") or "codex")
        common = [
            executable,
            "exec",
            "--json",
            "-a",
            "never",
            "-c",
            "sandbox_workspace_write.network_access=false",
        ]
        session_id = request.get("session_id")
        if session_id:
            argv = [*common, "resume", str(session_id), prompt]
        else:
            argv = [
                *common,
                "--sandbox",
                str(request.get("sandbox") or "workspace-write"),
                "-C",
                repo,
                "-o",
                str(last_message),
                (
                    "Do not commit, push, publish, change credentials, or modify files outside "
                    "the repository. Complete the requested coding work and run relevant tests.\n"
                    + prompt
                ),
            ]
    log_path = job_directory / "events.jsonl"
    found_session: str | None = None
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            argv,
            cwd=repo,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
        )
        assert process.stdout is not None
        for line in process.stdout:
            log.write(line)
            log.flush()
            found_session = _session_id(line) or found_session
        exit_code = process.wait()
    summary = ""
    if last_message.exists():
        summary = last_message.read_text(encoding="utf-8", errors="replace")[:100_000]
    elif log_path.exists():
        summary = log_path.read_text(encoding="utf-8", errors="replace")[-100_000:]
    result: dict[str, Any] = {
        "exit_code": exit_code,
        "session_id": found_session,
        "summary": summary,
        "log_path": str(log_path),
        "commit_performed_by_gateway": False,
        "push_performed_by_gateway": False,
    }
    temporary = job_directory / "status.json.tmp"
    temporary.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    temporary.replace(job_directory / "status.json")
    return exit_code


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m personal_agent.coding_runner JOB_DIRECTORY")
    raise SystemExit(run(Path(sys.argv[1]).resolve(strict=True)))


if __name__ == "__main__":
    main()
