from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

import httpx


class HomeAssistantClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        safe_scene_ids: tuple[str, ...] = (),
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.safe_scene_ids = frozenset(safe_scene_ids)
        self.transport = transport
        if self.base_url:
            self._validate_endpoint(self.base_url)

    @staticmethod
    def _validate_endpoint(value: str) -> None:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Home Assistant URL must be http(s)")
        hostname = parsed.hostname.lower()
        if hostname == "localhost" or hostname.endswith(".local"):
            return
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise ValueError("Home Assistant must use localhost, .local, or a private IP") from exc
        tailscale = ipaddress.ip_network("100.64.0.0/10")
        if not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address in tailscale
        ):
            raise ValueError("Public Home Assistant endpoints are disabled")

    def _ready(self) -> None:
        if not self.base_url or not self.token:
            raise RuntimeError("Home Assistant adapter is not configured")

    def assert_safe_scene(self, entity_id: str) -> None:
        if entity_id not in self.safe_scene_ids:
            raise PermissionError("Scene is not in PERSONAL_AGENT_HOME_ASSISTANT_SAFE_SCENES")

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    async def get_state(self, entity_id: str) -> dict[str, Any]:
        self._ready()
        async with httpx.AsyncClient(timeout=15, transport=self.transport) as client:
            response = await client.get(
                f"{self.base_url}/api/states/{entity_id}", headers=self.headers
            )
            response.raise_for_status()
            data = response.json()
        return {
            "entity_id": data.get("entity_id"),
            "state": data.get("state"),
            "attributes": data.get("attributes", {}),
            "last_updated": data.get("last_updated"),
        }

    async def call_service(self, domain: str, service: str, data: dict[str, Any]) -> dict[str, Any]:
        self._ready()
        async with httpx.AsyncClient(timeout=20, transport=self.transport) as client:
            response = await client.post(
                f"{self.base_url}/api/services/{domain}/{service}",
                headers=self.headers,
                json=data,
            )
            response.raise_for_status()
            result = response.json()
        return {"accepted": True, "changed_states": len(result) if isinstance(result, list) else 0}
