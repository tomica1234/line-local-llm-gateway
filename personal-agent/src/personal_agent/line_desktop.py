from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from .communication.models import CommunicationSource, NormalizedMessageCreate
from .config import Settings


class LineDesktopBridgeClient:
    source = CommunicationSource.LINE_DESKTOP

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        settings.validate_line_desktop_bridge_endpoint()
        self.base_url = settings.line_desktop_bridge_url
        self.token = settings.line_desktop_bridge_token
        self.timeout = settings.line_desktop_bridge_timeout_seconds
        self.send_enabled = settings.line_desktop_send_enabled
        self.transport = transport

    @property
    def headers(self) -> dict[str, str]:
        return {"X-Line-Desktop-Token": self.token}

    async def health(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            response = await client.get(f"{self.base_url}/health", headers=self.headers)
            response.raise_for_status()
            return response.json()

    async def snapshot(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            response = await client.post(f"{self.base_url}/snapshot", headers=self.headers, json={})
            response.raise_for_status()
            return response.json()

    async def search(
        self, *, task_id: str, query: str, limit: int
    ) -> list[NormalizedMessageCreate]:
        del task_id
        snapshot = await self.snapshot()
        normalized_query = query.strip().casefold()
        records: list[NormalizedMessageCreate] = []
        for item in snapshot.get("messages", []):
            haystack = f"{item.get('conversation_title', '')}\n{item.get('text', '')}".casefold()
            if normalized_query and normalized_query not in haystack:
                continue
            records.append(self.normalized_message(item))
            if len(records) >= limit:
                break
        return records

    async def sync_visible(self) -> list[NormalizedMessageCreate]:
        snapshot = await self.snapshot()
        return [self.normalized_message(item) for item in snapshot.get("messages", [])]

    async def send(
        self,
        *,
        conversation_id: str,
        subject: str,
        text: str,
        thread_id: str | None,
        reply_to: str | None,
        idempotency_key: str,
        task_id: str,
        action_id: str,
    ) -> dict[str, Any]:
        del subject, thread_id, reply_to
        if not self.send_enabled:
            raise PermissionError("LINE Desktop sending is disabled")
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            response = await client.post(
                f"{self.base_url}/send",
                headers=self.headers,
                json={
                    "conversation_id": conversation_id,
                    "text": text,
                    "idempotency_key": idempotency_key,
                    "task_id": task_id,
                    "action_id": action_id,
                    "approved": True,
                },
            )
            response.raise_for_status()
            return response.json()

    @staticmethod
    def normalized_message(item: dict[str, Any]) -> NormalizedMessageCreate:
        timestamp = str(item.get("timestamp") or datetime.now(UTC).isoformat())
        conversation_id = str(item["conversation_id"])
        message_id = str(item["message_id"])
        title = str(item.get("conversation_title") or "").strip()
        body = str(item["text"])
        text = f"{title}: {body}" if title else body
        return NormalizedMessageCreate(
            message_id=message_id,
            source=CommunicationSource.LINE_DESKTOP,
            conversation_id=conversation_id,
            timestamp=timestamp,
            text=text,
            permissions=["messages.read"],
            source_reference=str(
                item.get("source_reference") or f"line-desktop://{conversation_id}/{message_id}"
            ),
        )
