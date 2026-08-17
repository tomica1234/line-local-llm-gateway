from __future__ import annotations

import importlib.util
import json
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass

import httpx

from .browser_worker.config import BrowserWorkerSettings
from .config import Settings


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    status: str
    detail: str

    def model_dump(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


class DoctorService:
    """Read-only readiness checks. Details deliberately never contain credential values."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.worker = BrowserWorkerSettings.from_env()

    def run(self) -> list[DoctorCheck]:
        checks = [
            self._core(),
            self._model(),
            self._database(),
            self._browser_worker(),
            self._secret_worker(),
            self._line(),
            self._google("Gmail"),
            self._google("Google Calendar"),
            self._tailscale(),
            self._passkey(),
            self._home_assistant(),
            self._voice(),
        ]
        return checks

    @staticmethod
    def healthy(checks: list[DoctorCheck]) -> bool:
        return not any(item.status == "ERROR" for item in checks)

    def _core(self) -> DoctorCheck:
        try:
            response = httpx.get(f"http://127.0.0.1:{self.settings.port}/api/health", timeout=3)
            response.raise_for_status()
            return DoctorCheck("Core", "OK", "API reachable")
        except Exception as exc:
            return self._error("Core", exc)

    def _model(self) -> DoctorCheck:
        try:
            self.settings.validate_model_endpoint()
            headers = (
                {"Authorization": f"Bearer {self.settings.model_api_key}"}
                if self.settings.model_api_key
                else {}
            )
            response = httpx.get(
                f"{self.settings.model_base_url}/models", headers=headers, timeout=5
            )
            response.raise_for_status()
            return DoctorCheck("Model", "OK", f"{self.settings.model_name} endpoint reachable")
        except Exception as exc:
            return self._error("Model", exc)

    def _database(self) -> DoctorCheck:
        if not self.settings.db_path.exists():
            return DoctorCheck("Database", "ERROR", "database file does not exist")
        try:
            uri = f"file:{self.settings.db_path.resolve()}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=3) as connection:
                integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                migrations = int(
                    connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
                )
            return DoctorCheck(
                "Database",
                "OK" if integrity == "ok" else "ERROR",
                f"integrity={integrity}; migrations={migrations}",
            )
        except Exception as exc:
            return self._error("Database", exc)

    def _browser_worker(self) -> DoctorCheck:
        if not self.settings.browser_worker_token:
            return DoctorCheck("Browser Worker", "NOT_CONFIGURED", "worker token is not set")
        try:
            self.settings.validate_browser_worker_endpoint()
            response = httpx.get(
                f"{self.settings.browser_worker_base_url}/health",
                headers={"X-Browser-Worker-Token": self.settings.browser_worker_token},
                timeout=5,
            )
            response.raise_for_status()
            payload = response.json()
            return DoctorCheck(
                "Browser Worker",
                "OK",
                f"platform={payload.get('platform', 'unknown')}; headed={payload.get('headed')}",
            )
        except Exception as exc:
            return self._error("Browser Worker", exc)

    def _secret_worker(self) -> DoctorCheck:
        path = self.worker.secret_db_path
        if not path.exists():
            return DoctorCheck("Secret Worker", "NOT_CONFIGURED", "secret database is absent")
        try:
            uri = f"file:{path.resolve()}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=3) as connection:
                row = connection.execute(
                    "SELECT COUNT(*), COUNT(DISTINCT protection_backend) FROM credentials "
                    "WHERE enabled=1"
                ).fetchone()
            return DoctorCheck(
                "Secret Worker",
                "OK",
                f"enabled credential metadata={int(row[0])}; protection backends={int(row[1])}",
            )
        except Exception as exc:
            return self._error("Secret Worker", exc)

    def _line(self) -> DoctorCheck:
        if not self.settings.line_channel_access_token or not self.settings.line_primary_user_id:
            return DoctorCheck("LINE", "NOT_CONFIGURED", "Messaging API settings are incomplete")
        try:
            response = httpx.get(
                "https://api.line.me/v2/bot/info",
                headers={"Authorization": f"Bearer {self.settings.line_channel_access_token}"},
                timeout=5,
            )
            response.raise_for_status()
            return DoctorCheck("LINE", "OK", "Messaging API credential accepted")
        except Exception as exc:
            return self._error("LINE", exc)

    def _google(self, name: str) -> DoctorCheck:
        refs = {
            "refresh_credential_id": (
                self.settings.google_refresh_credential_id
                or (self.settings.gmail_credential_id if name == "Gmail" else "")
            ),
            "client_id_credential_id": self.settings.google_client_id_credential_id,
            "client_secret_credential_id": self.settings.google_client_secret_credential_id,
        }
        if not all(refs.values()):
            return DoctorCheck(name, "NOT_CONFIGURED", "Google OAuth references are incomplete")
        if not self.settings.browser_worker_token:
            return DoctorCheck(name, "ERROR", "Browser Worker token is not configured")
        try:
            response = httpx.post(
                f"{self.settings.browser_worker_base_url}/connectors/google/status",
                headers={"X-Browser-Worker-Token": self.settings.browser_worker_token},
                json={"credentials": refs, "task_id": "doctor-google-auth"},
                timeout=10,
            )
            response.raise_for_status()
            refreshed = response.json().get("refresh_succeeded") is True
            return DoctorCheck(
                name,
                "OK" if refreshed else "ERROR",
                "OAuth refresh succeeded" if refreshed else "OAuth refresh was not verified",
            )
        except Exception as exc:
            return self._error(name, exc)

    def _tailscale(self) -> DoctorCheck:
        executable = shutil.which("tailscale")
        if not executable:
            return DoctorCheck("Tailscale", "NOT_CONFIGURED", "tailscale CLI is unavailable")
        try:
            result = subprocess.run(
                [executable, "status", "--json"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            payload = json.loads(result.stdout)
            backend = payload.get("BackendState", "unknown")
            return DoctorCheck(
                "Tailscale", "OK" if backend == "Running" else "ERROR", f"state={backend}"
            )
        except Exception as exc:
            return self._error("Tailscale", exc)

    def _passkey(self) -> DoctorCheck:
        if not self.settings.webauthn_rp_id or not self.settings.webauthn_origin:
            return DoctorCheck("Passkey", "NOT_CONFIGURED", "WebAuthn RP is not configured")
        try:
            uri = f"file:{self.settings.db_path.resolve()}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=3) as connection:
                count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM webauthn_credentials WHERE revoked_at IS NULL"
                    ).fetchone()[0]
                )
            return DoctorCheck(
                "Passkey",
                "OK" if count else "ERROR",
                f"active credentials={count}",
            )
        except Exception as exc:
            return self._error("Passkey", exc)

    def _home_assistant(self) -> DoctorCheck:
        if not self.settings.home_assistant_url or not self.settings.home_assistant_token:
            return DoctorCheck("Home Assistant", "NOT_CONFIGURED", "connector is disabled")
        try:
            response = httpx.get(
                f"{self.settings.home_assistant_url.rstrip('/')}/api/",
                headers={"Authorization": f"Bearer {self.settings.home_assistant_token}"},
                timeout=5,
            )
            response.raise_for_status()
            return DoctorCheck("Home Assistant", "OK", "API credential accepted")
        except Exception as exc:
            return self._error("Home Assistant", exc)

    @staticmethod
    def _voice() -> DoctorCheck:
        packages = ("numpy", "sounddevice", "openwakeword")
        missing = [name for name in packages if importlib.util.find_spec(name) is None]
        if missing:
            return DoctorCheck(
                "Voice dependencies",
                "NOT_CONFIGURED",
                f"optional packages missing: {', '.join(missing)}",
            )
        return DoctorCheck("Voice dependencies", "OK", "local audio dependencies importable")

    @staticmethod
    def _error(name: str, exc: Exception) -> DoctorCheck:
        detail = type(exc).__name__
        if isinstance(exc, httpx.HTTPStatusError):
            detail = f"HTTP {exc.response.status_code}"
        elif isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout)):
            detail = "endpoint unreachable or timed out"
        return DoctorCheck(name, "ERROR", detail)


def doctor_report(settings: Settings, *, as_json: bool = False) -> tuple[str, bool]:
    checks = DoctorService(settings).run()
    if as_json:
        output = json.dumps([item.model_dump() for item in checks], ensure_ascii=False, indent=2)
    else:
        output = "\n".join(f"{item.name}: {item.status} — {item.detail}" for item in checks)
    return output, DoctorService.healthy(checks)
