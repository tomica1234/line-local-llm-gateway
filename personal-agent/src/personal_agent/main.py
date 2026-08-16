from __future__ import annotations

import uvicorn

from .app import create_app
from .config import Settings


def run() -> None:
    settings = Settings.from_env()
    settings.validate_runtime_security()
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    run()
