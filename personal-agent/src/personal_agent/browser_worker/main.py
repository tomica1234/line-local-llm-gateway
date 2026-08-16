from __future__ import annotations

import argparse
import platform
from pathlib import Path

import uvicorn

from .app import create_browser_worker_app
from .config import BrowserWorkerSettings


def run() -> None:
    parser = argparse.ArgumentParser(description="Run the Windows Browser Worker")
    parser.add_argument("--config", type=Path)
    arguments = parser.parse_args()
    settings = (
        BrowserWorkerSettings.from_json(arguments.config)
        if arguments.config
        else BrowserWorkerSettings.from_env()
    )
    if platform.system() != "Windows" and not settings.allow_non_windows:
        raise SystemExit(
            "Browser Worker must run on Windows. Set "
            "PERSONAL_AGENT_BROWSER_ALLOW_NON_WINDOWS=true only for local development/tests."
        )
    settings.validate_runtime_security()
    uvicorn.run(
        create_browser_worker_app(settings),
        host=settings.host,
        port=settings.port,
        log_level="info",
        access_log=False,
        log_config=None,
    )


if __name__ == "__main__":
    run()
