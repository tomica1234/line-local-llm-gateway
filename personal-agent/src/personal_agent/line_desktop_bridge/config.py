from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class LineDesktopBridgeSettings:
    host: str = "127.0.0.1"
    port: int = 18791
    token: str = ""
    database_path: Path = Path("line-desktop-bridge.sqlite3")
    send_enabled: bool = False
    send_allowlist: tuple[str, ...] = ()
    restore_minimized_window: bool = True
    core_ingest_url: str = ""
    sync_interval_seconds: int = 60

    @classmethod
    def from_json(cls, path: Path) -> LineDesktopBridgeSettings:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            host=str(data.get("host", "127.0.0.1")),
            port=int(data.get("port", 18791)),
            token=str(data.get("token", "")),
            database_path=Path(
                data.get("database_path", path.parent / "line-desktop-bridge.sqlite3")
            ),
            send_enabled=bool(data.get("send_enabled", False)),
            send_allowlist=tuple(str(item) for item in data.get("send_allowlist", [])),
            restore_minimized_window=bool(data.get("restore_minimized_window", True)),
            core_ingest_url=str(data.get("core_ingest_url", "")).rstrip("/"),
            sync_interval_seconds=int(data.get("sync_interval_seconds", 60)),
        )

    def validate(self) -> None:
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("LINE Desktop Bridge host must be a loopback IP") from exc
        if not address.is_loopback:
            raise ValueError("LINE Desktop Bridge must bind to loopback")
        if not 1 <= self.port <= 65_535:
            raise ValueError("LINE Desktop Bridge port is invalid")
        if len(self.token) < 32:
            raise ValueError("LINE Desktop Bridge token must contain at least 32 characters")
        if self.send_enabled and not self.send_allowlist:
            raise ValueError("Sending requires at least one allowlisted conversation ID")
        if not 10 <= self.sync_interval_seconds <= 86_400:
            raise ValueError("LINE Desktop sync interval must be between 10 and 86400 seconds")
        if self.core_ingest_url:
            parsed = urlparse(self.core_ingest_url)
            if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("LINE Desktop Core ingest URL must use loopback HTTP")
            if parsed.path != "/api/channels/line-desktop/ingest":
                raise ValueError("LINE Desktop Core ingest URL has an unexpected path")
