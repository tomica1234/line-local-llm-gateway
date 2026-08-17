from __future__ import annotations

import sys

import uvicorn

from .app import create_app
from .config import Settings
from .doctor import doctor_report


def run() -> None:
    settings = Settings.from_env()
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        unknown = [item for item in sys.argv[2:] if item != "--json"]
        if unknown:
            raise SystemExit(f"Unknown doctor option: {unknown[0]}")
        report, healthy = doctor_report(settings, as_json="--json" in sys.argv[2:])
        print(report)
        raise SystemExit(0 if healthy else 1)
    settings.validate_runtime_security()
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    run()
