from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _paths_env(name: str) -> tuple[Path, ...]:
    value = os.getenv(name, "")
    return tuple(Path(item).resolve() for item in value.split(os.pathsep) if item.strip())


def _csv_env(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, "").split(",") if item.strip())


@dataclass(frozen=True, slots=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8787
    db_path: Path = Path("data/personal-agent.sqlite3")
    user_id: str = "primary"
    timezone: str = "Asia/Tokyo"
    raw_event_retention_days: int = 90
    model_base_url: str = "http://127.0.0.1:8000/v1"
    model_name: str = "Qwen3.6-35B-A3B"
    model_api_key: str = ""
    model_timeout_seconds: float = 120.0
    model_enable_thinking: bool = False
    allow_remote_model: bool = False
    webauthn_rp_id: str = ""
    webauthn_origin: str = ""
    webauthn_rp_name: str = "Personal Agent"
    webauthn_challenge_ttl_seconds: int = 300
    webauthn_session_ttl_hours: int = 12
    tailscale_allowed_users: tuple[str, ...] = ()
    require_remote_passkey: bool = True
    admin_token: str = ""
    activity_token: str = ""
    browser_worker_base_url: str = "http://127.0.0.1:8790/v1"
    browser_worker_token: str = ""
    browser_worker_timeout_seconds: float = 45.0
    allow_remote_browser_worker: bool = False
    files_roots: tuple[Path, ...] = ()
    files_trash_root: Path = Path("data/files-trash")
    database_quota_bytes: int = 2 * 1024 * 1024 * 1024
    trash_quota_bytes: int = 1024 * 1024 * 1024
    home_assistant_url: str = ""
    home_assistant_token: str = ""
    home_assistant_safe_scenes: tuple[str, ...] = ()
    slack_credential_id: str = ""
    gmail_credential_id: str = ""
    line_channel_secret: str = ""
    line_channel_access_token: str = ""
    line_primary_user_id: str = ""
    line_desktop_bridge_url: str = "http://127.0.0.1:18791/v1"
    line_desktop_bridge_token: str = ""
    line_desktop_bridge_timeout_seconds: float = 20.0
    line_desktop_sync_interval_seconds: int = 60
    line_desktop_send_enabled: bool = False
    allow_remote_line_desktop_bridge: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            host=os.getenv("PERSONAL_AGENT_HOST", "127.0.0.1"),
            port=int(os.getenv("PERSONAL_AGENT_PORT", "8787")),
            db_path=Path(os.getenv("PERSONAL_AGENT_DB_PATH", "data/personal-agent.sqlite3")),
            user_id=os.getenv("PERSONAL_AGENT_USER_ID", "primary"),
            timezone=os.getenv("PERSONAL_AGENT_TIMEZONE", "Asia/Tokyo"),
            raw_event_retention_days=int(
                os.getenv("PERSONAL_AGENT_RAW_EVENT_RETENTION_DAYS", "90")
            ),
            model_base_url=os.getenv(
                "PERSONAL_AGENT_MODEL_BASE_URL", "http://127.0.0.1:8000/v1"
            ).rstrip("/"),
            model_name=os.getenv("PERSONAL_AGENT_MODEL_NAME", "Qwen3.6-35B-A3B"),
            model_api_key=os.getenv("PERSONAL_AGENT_MODEL_API_KEY", ""),
            model_timeout_seconds=float(os.getenv("PERSONAL_AGENT_MODEL_TIMEOUT_SECONDS", "120")),
            model_enable_thinking=_bool_env("PERSONAL_AGENT_MODEL_ENABLE_THINKING"),
            allow_remote_model=_bool_env("PERSONAL_AGENT_ALLOW_REMOTE_MODEL"),
            webauthn_rp_id=os.getenv("PERSONAL_AGENT_WEBAUTHN_RP_ID", "").strip().lower(),
            webauthn_origin=os.getenv("PERSONAL_AGENT_WEBAUTHN_ORIGIN", "").strip().rstrip("/"),
            webauthn_rp_name=os.getenv("PERSONAL_AGENT_WEBAUTHN_RP_NAME", "Personal Agent").strip(),
            webauthn_challenge_ttl_seconds=int(
                os.getenv("PERSONAL_AGENT_WEBAUTHN_CHALLENGE_TTL_SECONDS", "300")
            ),
            webauthn_session_ttl_hours=int(
                os.getenv("PERSONAL_AGENT_WEBAUTHN_SESSION_TTL_HOURS", "12")
            ),
            tailscale_allowed_users=tuple(
                value.casefold() for value in _csv_env("PERSONAL_AGENT_TAILSCALE_ALLOWED_USERS")
            ),
            require_remote_passkey=_bool_env(
                "PERSONAL_AGENT_REQUIRE_REMOTE_PASSKEY", default=True
            ),
            admin_token=os.getenv("PERSONAL_AGENT_ADMIN_TOKEN", ""),
            activity_token=os.getenv("PERSONAL_AGENT_ACTIVITY_TOKEN", ""),
            browser_worker_base_url=os.getenv(
                "PERSONAL_AGENT_BROWSER_WORKER_URL", "http://127.0.0.1:8790/v1"
            ).rstrip("/"),
            browser_worker_token=os.getenv("PERSONAL_AGENT_BROWSER_WORKER_TOKEN", ""),
            browser_worker_timeout_seconds=float(
                os.getenv("PERSONAL_AGENT_BROWSER_WORKER_TIMEOUT_SECONDS", "45")
            ),
            allow_remote_browser_worker=_bool_env("PERSONAL_AGENT_ALLOW_REMOTE_BROWSER_WORKER"),
            files_roots=_paths_env("PERSONAL_AGENT_FILES_ROOTS"),
            files_trash_root=Path(os.getenv("PERSONAL_AGENT_FILES_TRASH_ROOT", "data/files-trash")),
            database_quota_bytes=int(
                os.getenv("PERSONAL_AGENT_DATABASE_QUOTA_BYTES", str(2 * 1024**3))
            ),
            trash_quota_bytes=int(os.getenv("PERSONAL_AGENT_TRASH_QUOTA_BYTES", str(1024**3))),
            home_assistant_url=os.getenv("PERSONAL_AGENT_HOME_ASSISTANT_URL", "").rstrip("/"),
            home_assistant_token=os.getenv("PERSONAL_AGENT_HOME_ASSISTANT_TOKEN", ""),
            home_assistant_safe_scenes=_csv_env("PERSONAL_AGENT_HOME_ASSISTANT_SAFE_SCENES"),
            slack_credential_id=os.getenv("PERSONAL_AGENT_SLACK_CREDENTIAL_ID", ""),
            gmail_credential_id=os.getenv("PERSONAL_AGENT_GMAIL_CREDENTIAL_ID", ""),
            line_channel_secret=os.getenv("PERSONAL_AGENT_LINE_CHANNEL_SECRET", ""),
            line_channel_access_token=os.getenv("PERSONAL_AGENT_LINE_CHANNEL_ACCESS_TOKEN", ""),
            line_primary_user_id=os.getenv("PERSONAL_AGENT_LINE_PRIMARY_USER_ID", ""),
            line_desktop_bridge_url=os.getenv(
                "PERSONAL_AGENT_LINE_DESKTOP_BRIDGE_URL", "http://127.0.0.1:18791/v1"
            ).rstrip("/"),
            line_desktop_bridge_token=os.getenv(
                "PERSONAL_AGENT_LINE_DESKTOP_BRIDGE_TOKEN", ""
            ),
            line_desktop_bridge_timeout_seconds=float(
                os.getenv("PERSONAL_AGENT_LINE_DESKTOP_BRIDGE_TIMEOUT_SECONDS", "20")
            ),
            line_desktop_sync_interval_seconds=int(
                os.getenv("PERSONAL_AGENT_LINE_DESKTOP_SYNC_INTERVAL_SECONDS", "60")
            ),
            line_desktop_send_enabled=_bool_env("PERSONAL_AGENT_LINE_DESKTOP_SEND_ENABLED"),
            allow_remote_line_desktop_bridge=_bool_env(
                "PERSONAL_AGENT_ALLOW_REMOTE_LINE_DESKTOP_BRIDGE"
            ),
        )

    def validate_model_endpoint(self) -> None:
        self._validate_local_endpoint(
            self.model_base_url,
            allow_remote=self.allow_remote_model,
            variable="PERSONAL_AGENT_MODEL_BASE_URL",
            override="PERSONAL_AGENT_ALLOW_REMOTE_MODEL",
        )

    def validate_browser_worker_endpoint(self) -> None:
        self._validate_local_endpoint(
            self.browser_worker_base_url,
            allow_remote=self.allow_remote_browser_worker,
            variable="PERSONAL_AGENT_BROWSER_WORKER_URL",
            override="PERSONAL_AGENT_ALLOW_REMOTE_BROWSER_WORKER",
        )

    def validate_line_desktop_bridge_endpoint(self) -> None:
        self._validate_local_endpoint(
            self.line_desktop_bridge_url,
            allow_remote=self.allow_remote_line_desktop_bridge,
            variable="PERSONAL_AGENT_LINE_DESKTOP_BRIDGE_URL",
            override="PERSONAL_AGENT_ALLOW_REMOTE_LINE_DESKTOP_BRIDGE",
        )

    def validate_bind_host(self) -> None:
        if self.host == "localhost":
            return
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError(
                "PERSONAL_AGENT_HOST must be localhost, a loopback IP, or a Tailscale IP"
            ) from exc
        tailscale = ipaddress.ip_network("100.64.0.0/10")
        if not (address.is_loopback or address in tailscale):
            raise ValueError(
                "PERSONAL_AGENT_HOST must be localhost/loopback or 100.64.0.0/10 Tailscale"
            )

    def validate_runtime_security(self) -> None:
        self.validate_bind_host()
        self.validate_webauthn()
        if self.tailscale_allowed_users and self.require_remote_passkey and not self.webauthn_rp_id:
            raise ValueError(
                "WebAuthn RP ID/origin are required when remote passkey enforcement is enabled"
            )
        for identity in self.tailscale_allowed_users:
            invalid_character = any(ord(character) < 33 for character in identity)
            if not identity or len(identity) > 320 or invalid_character:
                raise ValueError(
                    "PERSONAL_AGENT_TAILSCALE_ALLOWED_USERS contains an invalid identity"
                )
        if len(self.admin_token) < 32:
            raise ValueError("PERSONAL_AGENT_ADMIN_TOKEN must contain at least 32 characters")
        for name, value in {
            "PERSONAL_AGENT_ACTIVITY_TOKEN": self.activity_token,
            "PERSONAL_AGENT_BROWSER_WORKER_TOKEN": self.browser_worker_token,
            "PERSONAL_AGENT_LINE_DESKTOP_BRIDGE_TOKEN": self.line_desktop_bridge_token,
        }.items():
            if value and len(value) < 32:
                raise ValueError(f"{name} must contain at least 32 characters when set")
        if not 10 <= self.line_desktop_sync_interval_seconds <= 86_400:
            raise ValueError(
                "PERSONAL_AGENT_LINE_DESKTOP_SYNC_INTERVAL_SECONDS must be 10..86400"
            )
        if self.line_desktop_bridge_token:
            self.validate_line_desktop_bridge_endpoint()
        line_values = (
            self.line_channel_secret,
            self.line_channel_access_token,
            self.line_primary_user_id,
        )
        if any(line_values) and not all(line_values):
            raise ValueError(
                "All PERSONAL_AGENT_LINE_CHANNEL_* and LINE_PRIMARY_USER_ID values "
                "must be configured together"
            )
        if self.line_primary_user_id and not re.fullmatch(
            r"U[0-9a-fA-F]{32}", self.line_primary_user_id
        ):
            raise ValueError(
                "PERSONAL_AGENT_LINE_PRIMARY_USER_ID must be a Messaging API user ID"
            )

    def validate_webauthn(self) -> None:
        if bool(self.webauthn_rp_id) != bool(self.webauthn_origin):
            raise ValueError(
                "PERSONAL_AGENT_WEBAUTHN_RP_ID and PERSONAL_AGENT_WEBAUTHN_ORIGIN "
                "must be configured together"
            )
        if not self.webauthn_rp_id:
            return
        parsed = urlparse(self.webauthn_origin)
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("PERSONAL_AGENT_WEBAUTHN_ORIGIN must be an exact web origin")
        if parsed.hostname.lower() != self.webauthn_rp_id:
            raise ValueError("WebAuthn RP ID must exactly match the configured origin hostname")
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("WebAuthn requires HTTPS except for localhost development")
        if not 60 <= self.webauthn_challenge_ttl_seconds <= 600:
            raise ValueError("WebAuthn challenge TTL must be between 60 and 600 seconds")
        if not 1 <= self.webauthn_session_ttl_hours <= 168:
            raise ValueError("WebAuthn session TTL must be between 1 and 168 hours")
        if not self.webauthn_rp_name:
            raise ValueError("PERSONAL_AGENT_WEBAUTHN_RP_NAME cannot be empty")

    @staticmethod
    def _validate_local_endpoint(
        endpoint: str, *, allow_remote: bool, variable: str, override: str
    ) -> None:
        if allow_remote:
            return
        parsed = urlparse(endpoint)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"{variable} must include a host")
        if hostname == "localhost":
            return
        try:
            if ipaddress.ip_address(hostname).is_loopback:
                return
        except ValueError:
            pass
        raise ValueError(
            f"Remote endpoint in {variable} is disabled. Use localhost/loopback or set "
            f"{override}=true explicitly."
        )
