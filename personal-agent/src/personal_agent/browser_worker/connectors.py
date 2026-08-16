from __future__ import annotations

import base64
import hashlib
import re
from datetime import UTC, datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import parseaddr
from enum import StrEnum
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import httpx
from pydantic import BaseModel, ConfigDict, Field

from ..secret.models import SecretAction
from ..secret.store import SecretStore
from .models import ActionContext, BrowserProfile
from .store import BrowserWorkerStore


class ConnectorProvider(StrEnum):
    SLACK = "slack"
    GMAIL = "gmail"


class ConnectorSendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    conversation_id: str = Field(min_length=1, max_length=512)
    subject: str = Field(default="", max_length=998)
    text: str = Field(min_length=1, max_length=100_000)
    thread_id: str | None = Field(default=None, max_length=512)
    reply_to: str | None = Field(default=None, max_length=512)
    context: ActionContext


class ConnectorSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    task_id: str = Field(min_length=1, max_length=128)
    query: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=20, ge=1, le=50)


class ConnectorWorkerService:
    _origins = {
        ConnectorProvider.SLACK: "https://slack.com",
        ConnectorProvider.GMAIL: "https://gmail.googleapis.com",
    }

    def __init__(
        self,
        secrets: SecretStore,
        store: BrowserWorkerStore,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.secrets = secrets
        self.store = store
        self.transport = transport

    async def send(
        self, provider: ConnectorProvider, request: ConnectorSendRequest
    ) -> dict[str, Any]:
        context = request.context
        action = f"connector.{provider.value}.send"
        disposition, previous = self.store.begin_action(
            profile=BrowserProfile.COMMUNICATION,
            idempotency_key=context.idempotency_key,
            task_id=context.task_id,
            action_id=context.action_id,
            action=action,
        )
        if disposition == "duplicate":
            if previous and previous.get("status") == "submitted_unknown":
                return {
                    **previous,
                    "resent": False,
                    "replay_suppressed": True,
                }
            return {**(previous or {}), "status": "duplicate"}
        if disposition == "in_progress":
            return {
                "status": "submitted_unknown",
                "verified": False,
                "resent": False,
            }
        if context.dry_run:
            result = {"status": "dry_run", "verified": False, "executed": False}
            self._finish(context.idempotency_key, result)
            return result

        origin = self._origins[provider]
        token = ""
        result = "error"
        try:
            token = self.secrets.value_for_use(
                credential_id=request.credential_id,
                origin=origin,
                action=SecretAction.CONNECTOR_REQUEST,
                task_id=context.task_id,
            )
            if provider is ConnectorProvider.SLACK:
                response = await self._send_slack(token, request)
            else:
                response = await self._send_gmail(token, request)
            result = "ok" if response.get("verified") else response.get("status", "error")
        except (httpx.TimeoutException, httpx.NetworkError):
            response = {
                "status": "submitted_unknown",
                "verified": False,
                "resent": False,
            }
            result = "submitted_unknown"
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code >= 500:
                response = {
                    "status": "submitted_unknown",
                    "verified": False,
                    "resent": False,
                }
                result = "submitted_unknown"
            else:
                response = {
                    "status": "error",
                    "verified": False,
                    "warnings": [f"HTTP_{exc.response.status_code}"],
                }
        except Exception as exc:
            response = {
                "status": "error",
                "verified": False,
                "warnings": [type(exc).__name__],
            }
        finally:
            token = ""
            self.secrets.record_use(
                credential_id=request.credential_id,
                task_id=context.task_id,
                origin=origin,
                action=SecretAction.CONNECTOR_REQUEST,
                result=result,
            )
        self._finish(context.idempotency_key, response)
        self.store.record_audit(
            profile=BrowserProfile.COMMUNICATION,
            task_id=context.task_id,
            actor="connector_worker",
            action=action,
            result=str(response.get("status")),
            details={
                "credential_id": request.credential_id,
                "conversation_id": request.conversation_id,
                "secret_value_recorded": False,
            },
        )
        return response

    async def search(
        self, provider: ConnectorProvider, request: ConnectorSearchRequest
    ) -> dict[str, Any]:
        origin = self._origins[provider]
        token = ""
        result = "error"
        try:
            token = self.secrets.value_for_use(
                credential_id=request.credential_id,
                origin=origin,
                action=SecretAction.CONNECTOR_REQUEST,
                task_id=request.task_id,
            )
            messages = (
                await self._search_slack(token, request)
                if provider is ConnectorProvider.SLACK
                else await self._search_gmail(token, request)
            )
            result = "ok"
            return {
                "status": "ok",
                "messages": messages,
                "trust_boundary": "untrusted_external_content",
            }
        finally:
            token = ""
            self.secrets.record_use(
                credential_id=request.credential_id,
                task_id=request.task_id,
                origin=origin,
                action=SecretAction.CONNECTOR_REQUEST,
                result=result,
            )

    async def _send_slack(self, token: str, request: ConnectorSendRequest) -> dict[str, Any]:
        if not re.fullmatch(r"[CDGU][A-Z0-9]{8,30}", request.conversation_id):
            raise ValueError("Slack sends require an exact channel or conversation ID")
        payload: dict[str, Any] = {
            "channel": request.conversation_id,
            "text": request.text,
            "client_msg_id": str(uuid5(NAMESPACE_URL, request.context.idempotency_key)),
        }
        if request.thread_id:
            if not re.fullmatch(r"\d{10,}\.[0-9]{6}", request.thread_id):
                raise ValueError("Slack thread_id must be an exact thread timestamp")
            payload["thread_ts"] = request.thread_id
        async with httpx.AsyncClient(timeout=30, transport=self.transport) as client:
            response = await client.post(
                "https://slack.com/api/chat.postMessage",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        if not data.get("ok"):
            return {
                "status": "error",
                "verified": False,
                "provider_error": str(data.get("error", "unknown_error")),
            }
        return {
            "status": "ok",
            "verified": True,
            "provider": "slack",
            "external_message_id": str(data["ts"]),
            "conversation_id": str(data.get("channel") or request.conversation_id),
        }

    async def _send_gmail(self, token: str, request: ConnectorSendRequest) -> dict[str, Any]:
        _, address = parseaddr(request.conversation_id)
        if address != request.conversation_id or "@" not in address:
            raise ValueError("Gmail sends require one exact recipient email address")
        if any("\n" in value or "\r" in value for value in (address, request.subject)):
            raise ValueError("Email headers contain forbidden newline characters")
        message = EmailMessage()
        message["To"] = address
        message["Subject"] = request.subject or "Personal Agent"
        message["Message-ID"] = (
            f"<{hashlib.sha256(request.context.idempotency_key.encode()).hexdigest()}"
            "@personal-agent.local>"
        )
        if request.reply_to:
            if "\n" in request.reply_to or "\r" in request.reply_to:
                raise ValueError("Email reply reference contains forbidden newlines")
            message["In-Reply-To"] = request.reply_to
            message["References"] = request.reply_to
        message.set_content(request.text)
        raw = base64.urlsafe_b64encode(message.as_bytes(policy=SMTP)).decode().rstrip("=")
        payload: dict[str, Any] = {"raw": raw}
        if request.thread_id:
            payload["threadId"] = request.thread_id
        async with httpx.AsyncClient(timeout=30, transport=self.transport) as client:
            response = await client.post(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            if response.status_code >= 500:
                return {"status": "submitted_unknown", "verified": False, "resent": False}
            response.raise_for_status()
            data = response.json()
        verified = bool(data.get("id"))
        return {
            "status": "ok" if verified else "error",
            "verified": verified,
            "provider": "gmail",
            "external_message_id": str(data.get("id", "")),
            "thread_id": data.get("threadId"),
        }

    async def _search_slack(
        self, token: str, request: ConnectorSearchRequest
    ) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=30, transport=self.transport) as client:
            response = await client.get(
                "https://slack.com/api/search.messages",
                headers={"Authorization": f"Bearer {token}"},
                params={
                    "query": request.query,
                    "count": request.limit,
                    "sort": "timestamp",
                    "sort_dir": "desc",
                    "highlight": "false",
                },
            )
            response.raise_for_status()
            data = response.json()
        if not data.get("ok"):
            raise RuntimeError(f"Slack search failed: {data.get('error', 'unknown_error')}")
        messages = []
        for item in data.get("messages", {}).get("matches", [])[: request.limit]:
            channel = item.get("channel") or {}
            channel_id = str(channel.get("id") or "")
            timestamp = str(item.get("ts") or "0")
            messages.append(
                {
                    "message_id": str(item.get("iid") or timestamp),
                    "source": "slack",
                    "conversation_id": channel_id,
                    "thread_id": item.get("thread_ts"),
                    "sender_entity_id": None,
                    "timestamp": datetime.fromtimestamp(float(timestamp), UTC).isoformat(),
                    "text": str(item.get("text") or "").replace("\ue000", "").replace("\ue001", ""),
                    "attachments": [],
                    "reply_to": None,
                    "permissions": ["messages.read"],
                    "source_reference": str(
                        item.get("permalink") or f"slack://{channel_id}/{timestamp}"
                    ),
                }
            )
        return messages

    async def _search_gmail(
        self, token: str, request: ConnectorSearchRequest
    ) -> list[dict[str, Any]]:
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=30, transport=self.transport) as client:
            listed = await client.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                headers=headers,
                params={"q": request.query, "maxResults": request.limit},
            )
            listed.raise_for_status()
            messages = []
            for reference in listed.json().get("messages", [])[: request.limit]:
                response = await client.get(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{reference['id']}",
                    headers=headers,
                    params={"format": "full"},
                )
                response.raise_for_status()
                messages.append(self._gmail_message(response.json()))
        return messages

    @classmethod
    def _gmail_message(cls, item: dict[str, Any]) -> dict[str, Any]:
        payload = item.get("payload") or {}
        headers = {
            str(entry.get("name", "")).casefold(): str(entry.get("value", ""))
            for entry in payload.get("headers", [])
        }
        message_id = str(item["id"])
        body = cls._gmail_body(payload) or str(item.get("snippet") or "")
        timestamp = datetime.fromtimestamp(
            int(item.get("internalDate", "0")) / 1_000, UTC
        ).isoformat()
        return {
            "message_id": message_id,
            "source": "email",
            "conversation_id": str(item.get("threadId") or message_id),
            "thread_id": item.get("threadId"),
            "sender_entity_id": None,
            "timestamp": timestamp,
            "text": body,
            "attachments": [],
            "reply_to": headers.get("in-reply-to"),
            "permissions": ["messages.read"],
            "source_reference": f"gmail://message/{message_id}",
        }

    @classmethod
    def _gmail_body(cls, payload: dict[str, Any]) -> str:
        mime_type = str(payload.get("mimeType") or "")
        data = (payload.get("body") or {}).get("data")
        if data and mime_type == "text/plain":
            try:
                padded = str(data) + "=" * (-len(str(data)) % 4)
                return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                return ""
        for part in payload.get("parts") or []:
            result = cls._gmail_body(part)
            if result:
                return result
        return ""

    def _finish(self, idempotency_key: str, result: dict[str, Any]) -> None:
        self.store.finish_action(
            profile=BrowserProfile.COMMUNICATION,
            idempotency_key=idempotency_key,
            result=result,
        )
