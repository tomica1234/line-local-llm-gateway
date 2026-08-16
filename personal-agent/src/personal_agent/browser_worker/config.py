from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _domains(value: str) -> tuple[str, ...]:
    domains = {item.strip().lower().strip(".") for item in value.split(",") if item.strip()}
    return tuple(sorted(domains))


def _paths(value: str) -> tuple[Path, ...]:
    return tuple(Path(item).resolve() for item in value.split(os.pathsep) if item.strip())


def _cidrs(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True, slots=True)
class BrowserWorkerSettings:
    host: str = "127.0.0.1"
    port: int = 8790
    token: str = ""
    profile_root: Path = Path("data/browser-profiles")
    quarantine_root: Path = Path("data/browser-downloads")
    state_db_path: Path = Path("data/browser-worker.sqlite3")
    browser_channel: str = "chrome"
    headless: bool = False
    finance_allowlist: tuple[str, ...] = ()
    takeover_timeout_seconds: int = 300
    navigation_timeout_ms: int = 30_000
    core_base_url: str = "http://127.0.0.1:8787"
    secret_db_path: Path = Path("data/secrets.sqlite3")
    upload_roots: tuple[Path, ...] = ()
    allow_private_navigation: bool = False
    allow_non_windows: bool = False
    allowed_client_cidrs: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> BrowserWorkerSettings:
        return cls(
            host=os.getenv("PERSONAL_AGENT_BROWSER_WORKER_HOST", "127.0.0.1"),
            port=int(os.getenv("PERSONAL_AGENT_BROWSER_WORKER_PORT", "8790")),
            token=os.getenv("PERSONAL_AGENT_BROWSER_WORKER_TOKEN", ""),
            profile_root=Path(
                os.getenv("PERSONAL_AGENT_BROWSER_PROFILE_ROOT", "data/browser-profiles")
            ),
            quarantine_root=Path(
                os.getenv("PERSONAL_AGENT_BROWSER_QUARANTINE_ROOT", "data/browser-downloads")
            ),
            state_db_path=Path(
                os.getenv("PERSONAL_AGENT_BROWSER_STATE_DB", "data/browser-worker.sqlite3")
            ),
            browser_channel=os.getenv("PERSONAL_AGENT_BROWSER_CHANNEL", "chrome").strip(),
            headless=_bool_env("PERSONAL_AGENT_BROWSER_HEADLESS"),
            finance_allowlist=_domains(os.getenv("PERSONAL_AGENT_BROWSER_FINANCE_ALLOWLIST", "")),
            takeover_timeout_seconds=int(
                os.getenv("PERSONAL_AGENT_BROWSER_TAKEOVER_TIMEOUT_SECONDS", "300")
            ),
            navigation_timeout_ms=int(
                os.getenv("PERSONAL_AGENT_BROWSER_NAVIGATION_TIMEOUT_MS", "30000")
            ),
            core_base_url=os.getenv(
                "PERSONAL_AGENT_BROWSER_CORE_URL", "http://127.0.0.1:8787"
            ).rstrip("/"),
            secret_db_path=Path(os.getenv("PERSONAL_AGENT_SECRET_DB_PATH", "data/secrets.sqlite3")),
            upload_roots=_paths(os.getenv("PERSONAL_AGENT_BROWSER_UPLOAD_ROOTS", "")),
            allow_private_navigation=_bool_env("PERSONAL_AGENT_BROWSER_ALLOW_PRIVATE_NAVIGATION"),
            allow_non_windows=_bool_env("PERSONAL_AGENT_BROWSER_ALLOW_NON_WINDOWS"),
            allowed_client_cidrs=_cidrs(
                os.getenv("PERSONAL_AGENT_BROWSER_ALLOWED_CLIENT_CIDRS", "")
            ),
        )

    @classmethod
    def from_json(cls, path: Path) -> BrowserWorkerSettings:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            host=str(data.get("host", "127.0.0.1")),
            port=int(data.get("port", 18790)),
            token=str(data.get("token", "")),
            profile_root=Path(data["profile_root"]),
            quarantine_root=Path(data["quarantine_root"]),
            state_db_path=Path(data["state_db_path"]),
            browser_channel=str(data.get("browser_channel", "chrome")),
            headless=bool(data.get("headless", False)),
            finance_allowlist=tuple(str(item) for item in data.get("finance_allowlist", [])),
            takeover_timeout_seconds=int(data.get("takeover_timeout_seconds", 300)),
            navigation_timeout_ms=int(data.get("navigation_timeout_ms", 30_000)),
            core_base_url=str(data.get("core_base_url", "http://127.0.0.1:8789")).rstrip(
                "/"
            ),
            secret_db_path=Path(data["secret_db_path"]),
            upload_roots=tuple(Path(item) for item in data.get("upload_roots", [])),
            allow_private_navigation=bool(data.get("allow_private_navigation", False)),
            allow_non_windows=bool(data.get("allow_non_windows", False)),
            allowed_client_cidrs=tuple(
                str(item) for item in data.get("allowed_client_cidrs", [])
            ),
        )

    def validate_bind_host(self) -> None:
        if self.host == "localhost":
            return
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("Browser Worker must bind to loopback") from exc
        if address.is_loopback:
            return
        if not self.allowed_client_cidrs:
            raise ValueError("Non-loopback Browser Worker requires allowed client CIDRs")
        if not (address.is_private or address.is_unspecified):
            raise ValueError("Browser Worker may only bind to loopback or a private interface")

    def client_allowed(self, host: str) -> bool:
        if not self.allowed_client_cidrs:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(
            address in ipaddress.ip_network(network, strict=False)
            for network in self.allowed_client_cidrs
        )

    def validate_runtime_security(self) -> None:
        self.validate_bind_host()
        if len(self.token) < 32:
            raise ValueError(
                "PERSONAL_AGENT_BROWSER_WORKER_TOKEN must contain at least 32 characters"
            )
        for network in self.allowed_client_cidrs:
            parsed = ipaddress.ip_network(network, strict=False)
            if not parsed.is_private:
                raise ValueError("Browser Worker allowed client CIDRs must be private")
