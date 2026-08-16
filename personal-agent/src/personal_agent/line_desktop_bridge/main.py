from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from .app import create_line_desktop_bridge_app
from .config import LineDesktopBridgeSettings


def run() -> None:
    parser = argparse.ArgumentParser(description="Run the Windows LINE Desktop OCR bridge")
    parser.add_argument("--config", type=Path, required=True)
    arguments = parser.parse_args()
    settings = LineDesktopBridgeSettings.from_json(arguments.config)
    settings.validate()
    uvicorn.run(
        create_line_desktop_bridge_app(settings),
        host=settings.host,
        port=settings.port,
        log_level="info",
        access_log=False,
        # pythonw.exe has no stdout/stderr. Uvicorn's default logging setup
        # probes those streams and exits before binding the loopback socket.
        log_config=None,
    )


if __name__ == "__main__":
    run()
