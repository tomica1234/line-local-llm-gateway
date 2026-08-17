from __future__ import annotations

import base64
import ipaddress
import socket
import struct
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from ..browser_worker.models import ActionContext, BrowserAction, BrowserProfile
from ..config import Settings
from ..secret.models import SecretPutRequest


class BrowserWorkerClient:
    def __init__(self, settings: Settings):
        settings.validate_browser_worker_endpoint()
        self.base_url = self._resolve_wsl_host(settings.browser_worker_base_url)
        self.token = settings.browser_worker_token
        self.timeout = settings.browser_worker_timeout_seconds

    @property
    def headers(self) -> dict[str, str]:
        return {"X-Browser-Worker-Token": self.token}

    @staticmethod
    def _resolve_wsl_host(url: str) -> str:
        parsed = urlsplit(url)
        if parsed.hostname != "wsl-host":
            return url
        gateway = None
        try:
            for line in open("/proc/net/route", encoding="ascii").read().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                    break
        except (OSError, ValueError, struct.error):
            pass
        if gateway is None or not ipaddress.ip_address(gateway).is_private:
            raise RuntimeError("Could not resolve the private Windows host from WSL")
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme, f"{gateway}{port}", parsed.path, parsed.query, ""))

    async def execute(
        self,
        *,
        profile: BrowserProfile,
        action: BrowserAction,
        params: dict[str, Any],
        context: ActionContext | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"params": params}
        if context is not None:
            payload["context"] = context.model_dump(mode="json")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/browser/{profile.value}/{action.value}",
                headers=self.headers,
                json=payload,
            )
            response.raise_for_status()
            return response.json()

    async def profiles(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/profiles", headers=self.headers)
            response.raise_for_status()
            return response.json()

    async def health(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/health", headers=self.headers)
            response.raise_for_status()
            return response.json()

    async def quarantined_image(self, path: str) -> tuple[bytes, str]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/quarantine/image",
                headers=self.headers,
                json={"path": path},
            )
            response.raise_for_status()
            payload = response.json()
        return base64.b64decode(payload["content_base64"]), str(payload["media_type"])

    async def close_profile(self, profile: BrowserProfile) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.delete(
                f"{self.base_url}/profiles/{profile.value}", headers=self.headers
            )
            response.raise_for_status()
            return response.json()

    async def takeover_status(self, profile: BrowserProfile) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                f"{self.base_url}/takeover/{profile.value}", headers=self.headers
            )
            response.raise_for_status()
            return response.json()

    async def release_takeover(self, profile: BrowserProfile, *, outcome: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/takeover/{profile.value}/release",
                headers=self.headers,
                json={"outcome": outcome},
            )
            response.raise_for_status()
            return response.json()

    async def ensure_authenticated(
        self,
        *,
        profile: BrowserProfile,
        account_label: str | None,
        context: ActionContext,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/auth/{profile.value}/ensure",
                headers=self.headers,
                json={
                    "account_label": account_label,
                    "context": context.model_dump(mode="json"),
                },
            )
            response.raise_for_status()
            return response.json()

    async def auth_sessions(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/auth/sessions", headers=self.headers)
            response.raise_for_status()
            return response.json()

    async def submit_auth_otp(
        self,
        *,
        profile: BrowserProfile,
        auth_session_id: str,
        code: str,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/auth/{profile.value}/otp",
                    headers=self.headers,
                    json={"auth_session_id": auth_session_id, "code": code},
                )
                response.raise_for_status()
                return response.json()
        finally:
            code = ""

    async def secret_metadata(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/secrets", headers=self.headers)
            response.raise_for_status()
            return response.json()

    async def put_secret(self, request: SecretPutRequest) -> dict[str, Any]:
        value = request.value.get_secret_value()
        payload = request.model_dump(mode="json", exclude={"value"})
        payload["value"] = value
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/secrets",
                    headers=self.headers,
                    json=payload,
                )
                response.raise_for_status()
                return response.json()
        finally:
            value = ""
            payload.pop("value", None)

    async def secret_usage(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/secrets/usage", headers=self.headers)
            response.raise_for_status()
            return response.json()

    async def disable_secret(self, credential_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.delete(
                f"{self.base_url}/secrets/{quote(credential_id, safe='')}",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def connector_send(
        self,
        *,
        provider: str,
        credential_id: str,
        conversation_id: str,
        subject: str,
        text: str,
        thread_id: str | None,
        reply_to: str | None,
        context: ActionContext,
        oauth_client_id_credential_id: str | None = None,
        oauth_client_secret_credential_id: str | None = None,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/connectors/{provider}/send",
                headers=self.headers,
                json={
                    "credential_id": credential_id,
                    "conversation_id": conversation_id,
                    "subject": subject,
                    "text": text,
                    "thread_id": thread_id,
                    "reply_to": reply_to,
                    "oauth_client_id_credential_id": oauth_client_id_credential_id,
                    "oauth_client_secret_credential_id": oauth_client_secret_credential_id,
                    "context": context.model_dump(mode="json"),
                },
            )
            response.raise_for_status()
            return response.json()

    async def connector_search(
        self,
        *,
        provider: str,
        credential_id: str,
        task_id: str,
        query: str,
        limit: int,
        oauth_client_id_credential_id: str | None = None,
        oauth_client_secret_credential_id: str | None = None,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/connectors/{provider}/search",
                headers=self.headers,
                json={
                    "credential_id": credential_id,
                    "task_id": task_id,
                    "query": query,
                    "limit": limit,
                    "oauth_client_id_credential_id": oauth_client_id_credential_id,
                    "oauth_client_secret_credential_id": oauth_client_secret_credential_id,
                },
            )
            response.raise_for_status()
            return response.json()

    async def google_calendar_request(
        self,
        *,
        refresh_credential_id: str,
        client_id_credential_id: str,
        client_secret_credential_id: str,
        task_id: str,
        operation: str,
        calendar_id: str,
        event_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/connectors/google-calendar",
                headers=self.headers,
                json={
                    "credentials": {
                        "refresh_credential_id": refresh_credential_id,
                        "client_id_credential_id": client_id_credential_id,
                        "client_secret_credential_id": client_secret_credential_id,
                    },
                    "task_id": task_id,
                    "operation": operation,
                    "calendar_id": calendar_id,
                    "event_id": event_id,
                    "payload": payload or {},
                },
            )
            response.raise_for_status()
            return response.json()

    async def google_oauth_start(
        self,
        *,
        task_id: str,
        client_id_credential_id: str,
        client_secret_credential_id: str,
        refresh_credential_id: str,
        redirect_uri: str,
        scopes: list[str],
        account_label: str,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/connectors/google/oauth/start",
                headers=self.headers,
                json={
                    "task_id": task_id,
                    "client_id_credential_id": client_id_credential_id,
                    "client_secret_credential_id": client_secret_credential_id,
                    "refresh_credential_id": refresh_credential_id,
                    "redirect_uri": redirect_uri,
                    "scopes": scopes,
                    "account_label": account_label,
                },
            )
            response.raise_for_status()
            return response.json()

    async def google_oauth_exchange(self, *, state: str, code: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/connectors/google/oauth/exchange",
                    headers=self.headers,
                    json={"state": state, "code": code},
                )
                response.raise_for_status()
                return response.json()
        finally:
            code = ""

    async def gmail_attachment(
        self,
        *,
        refresh_credential_id: str,
        client_id_credential_id: str,
        client_secret_credential_id: str,
        task_id: str,
        message_id: str,
        attachment_id: str,
        filename: str,
        media_type: str,
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=max(self.timeout, 60)) as client:
            response = await client.post(
                f"{self.base_url}/connectors/gmail/attachment",
                headers=self.headers,
                json={
                    "credentials": {
                        "refresh_credential_id": refresh_credential_id,
                        "client_id_credential_id": client_id_credential_id,
                        "client_secret_credential_id": client_secret_credential_id,
                    },
                    "task_id": task_id,
                    "message_id": message_id,
                    "attachment_id": attachment_id,
                    "filename": filename,
                    "media_type": media_type,
                },
            )
            response.raise_for_status()
            return response.json()
