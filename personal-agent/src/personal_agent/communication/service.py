from __future__ import annotations

from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

import httpx

from ..browser.client import BrowserWorkerClient
from ..browser_worker.models import ActionContext
from ..memory.models import EventCreate, PrivacyLevel, TrustLevel
from ..memory.store import MemoryStore
from ..types import RiskLevel
from .models import CommunicationSource, DraftCreate, DraftRecord, NormalizedMessageCreate
from .store import CommunicationStore


class CommunicationAdapter(Protocol):
    source: CommunicationSource

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
    ) -> dict[str, Any]: ...


class LinePushAdapter:
    source = CommunicationSource.LINE

    def __init__(
        self,
        *,
        access_token: str,
        primary_user_id: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.access_token = access_token
        self.primary_user_id = primary_user_id
        self.transport = transport

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
        if conversation_id != self.primary_user_id:
            raise PermissionError("LINE push is restricted to the configured primary user")
        retry_key = str(uuid5(NAMESPACE_URL, idempotency_key))
        try:
            async with httpx.AsyncClient(timeout=30, transport=self.transport) as client:
                response = await client.post(
                    "https://api.line.me/v2/bot/message/push",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                        "X-Line-Retry-Key": retry_key,
                    },
                    json={
                        "to": conversation_id,
                        "messages": [{"type": "text", "text": text}],
                    },
                )
        except (httpx.TimeoutException, httpx.NetworkError):
            return {
                "status": "submitted_unknown",
                "provider": "line",
                "verified": False,
                "resent": False,
            }
        if response.status_code >= 500:
            return {
                "status": "submitted_unknown",
                "provider": "line",
                "verified": False,
                "resent": False,
            }
        if response.status_code == 409:
            accepted_id = response.headers.get("x-line-accepted-request-id")
            if accepted_id:
                return {
                    "status": "ok",
                    "external_message_id": accepted_id,
                    "provider": "line",
                    "verified": True,
                    "provider_duplicate": True,
                }
        response.raise_for_status()
        request_id = response.headers.get("x-line-request-id")
        return {
            "status": "ok" if request_id else "error",
            "external_message_id": request_id,
            "provider": "line",
            "verified": bool(request_id),
        }


class WorkerCommunicationAdapter:
    def __init__(
        self,
        *,
        source: CommunicationSource,
        provider: str,
        credential_id: str,
        worker: BrowserWorkerClient,
        oauth_client_id_credential_id: str | None = None,
        oauth_client_secret_credential_id: str | None = None,
    ) -> None:
        if source not in {CommunicationSource.SLACK, CommunicationSource.EMAIL}:
            raise ValueError("Worker connector only supports Slack and email")
        self.source = source
        self.provider = provider
        self.credential_id = credential_id
        self.worker = worker
        self.oauth_client_id_credential_id = oauth_client_id_credential_id
        self.oauth_client_secret_credential_id = oauth_client_secret_credential_id

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
        return await self.worker.connector_send(
            provider=self.provider,
            credential_id=self.credential_id,
            conversation_id=conversation_id,
            subject=subject,
            text=text,
            thread_id=thread_id,
            reply_to=reply_to,
            context=ActionContext(
                task_id=task_id,
                action_id=action_id,
                idempotency_key=idempotency_key,
                dry_run=False,
                reason="Approved communication draft send",
                risk_level=RiskLevel.R2,
            ),
            oauth_client_id_credential_id=self.oauth_client_id_credential_id,
            oauth_client_secret_credential_id=self.oauth_client_secret_credential_id,
        )

    async def search(
        self, *, task_id: str, query: str, limit: int
    ) -> list[NormalizedMessageCreate]:
        result = await self.worker.connector_search(
            provider=self.provider,
            credential_id=self.credential_id,
            task_id=task_id,
            query=query,
            limit=limit,
            oauth_client_id_credential_id=self.oauth_client_id_credential_id,
            oauth_client_secret_credential_id=self.oauth_client_secret_credential_id,
        )
        return [NormalizedMessageCreate.model_validate(item) for item in result.get("messages", [])]


class CommunicationService:
    def __init__(
        self,
        store: CommunicationStore,
        memory: MemoryStore,
        *,
        user_id: str,
    ) -> None:
        self.store = store
        self.memory = memory
        self.user_id = user_id
        self.adapters: dict[CommunicationSource, CommunicationAdapter] = {}

    def register(self, adapter: CommunicationAdapter, *, scopes: list[str]) -> None:
        self.adapters[adapter.source] = adapter
        existing = self.store.connector(adapter.source)
        if existing["status"] == "missing":
            self.store.configure_connector(adapter.source, enabled=True, scopes=scopes)

    def ingest(self, message: NormalizedMessageCreate) -> bool:
        stored = self.store.ingest(message)
        if stored:
            self.memory.append_event(
                user_id=self.user_id,
                event=EventCreate(
                    event_type="communication.message.received",
                    source=message.source.value,
                    content=message.text,
                    payload={
                        "message_id": message.message_id,
                        "conversation_id": message.conversation_id,
                        "thread_id": message.thread_id,
                        "sender_entity_id": message.sender_entity_id,
                    },
                    timestamp=message.timestamp,
                    provenance={"adapter": message.source.value},
                    trust_level=TrustLevel.UNTRUSTED,
                    privacy_level=PrivacyLevel.STANDARD,
                    source_reference=message.source_reference,
                ),
            )
        return stored

    def draft(self, *, task_id: str, draft: DraftCreate) -> DraftRecord:
        entity = self.memory.get_entity(draft.recipient_entity_id)
        if entity["user_id"] != self.user_id:
            raise PermissionError("Recipient entity is not owned by this user")
        conversation_id = self._conversation_id(entity, draft.source)
        return self.store.create_draft(
            task_id=task_id,
            source=draft.source,
            recipient_entity_id=draft.recipient_entity_id,
            conversation_id=conversation_id,
            subject=draft.subject,
            text=draft.text,
            thread_id=draft.thread_id,
            reply_to=draft.reply_to,
            attachments=[item.model_dump(mode="json") for item in draft.attachments],
        )

    async def send(
        self,
        *,
        draft_id: str,
        idempotency_key: str,
        action_id: str,
    ) -> DraftRecord:
        draft = self.store.get_draft(draft_id)
        if draft.state == "sent":
            return draft
        connector = self.store.connector(draft.source)
        if not connector["enabled"] or "messages.write" not in connector["scopes"]:
            raise PermissionError("Connector does not grant messages.write")
        adapter = self.adapters.get(draft.source)
        if adapter is None:
            raise RuntimeError(f"No active adapter for {draft.source.value}")
        evidence = await adapter.send(
            conversation_id=draft.conversation_id,
            subject=draft.subject,
            text=draft.text,
            thread_id=draft.thread_id,
            reply_to=draft.reply_to,
            idempotency_key=idempotency_key,
            task_id=draft.task_id,
            action_id=action_id,
        )
        if evidence.get("status") == "submitted_unknown":
            return self.store.mark_submission_unknown(draft_id, evidence=evidence)
        if not evidence.get("verified"):
            raise RuntimeError("Provider did not verify message acceptance")
        sent = self.store.mark_sent(
            draft_id,
            external_message_id=str(evidence["external_message_id"]),
            evidence=evidence,
        )
        self.memory.append_event(
            user_id=self.user_id,
            event=EventCreate(
                event_type="communication.message.sent",
                source=draft.source.value,
                content=draft.text,
                payload={
                    "draft_id": draft.draft_id,
                    "recipient_entity_id": draft.recipient_entity_id,
                    "external_message_id": sent.external_message_id,
                },
                provenance={"adapter": draft.source.value},
                trust_level=TrustLevel.SYSTEM,
                privacy_level=PrivacyLevel.STANDARD,
                source_reference=f"{draft.source.value}://message/{sent.external_message_id}",
            ),
        )
        return sent

    async def sync(
        self,
        *,
        source: CommunicationSource,
        task_id: str,
        query: str,
        limit: int,
    ) -> dict[str, Any]:
        connector = self.store.connector(source)
        if not connector["enabled"] or "messages.read" not in connector["scopes"]:
            raise PermissionError("Connector does not grant messages.read")
        adapter = self.adapters.get(source)
        search = getattr(adapter, "search", None) if adapter else None
        if search is None:
            raise RuntimeError(f"No searchable adapter for {source.value}")
        messages = await search(task_id=task_id, query=query, limit=limit)
        stored = sum(self.ingest(message) for message in messages)
        return {
            "source": source.value,
            "received": len(messages),
            "stored": stored,
            "message_ids": [message.message_id for message in messages],
            "trust_boundary": "untrusted_external_content",
        }

    @staticmethod
    def _conversation_id(entity: dict[str, Any], source: CommunicationSource) -> str:
        communication = entity.get("metadata", {}).get("communication", {})
        identity = communication.get(source.value)
        if not isinstance(identity, dict):
            raise ValueError("Recipient entity has no identity for the selected connector")
        conversation_id = identity.get("conversation_id") or identity.get("address")
        if not isinstance(conversation_id, str) or not conversation_id:
            raise ValueError("Recipient connector identity is incomplete")
        return conversation_id
