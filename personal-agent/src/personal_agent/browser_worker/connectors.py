from __future__ import annotations

import base64
import hashlib
import re
import secrets
from datetime import UTC, datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import parseaddr
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlencode, urlsplit
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx
from pydantic import BaseModel, ConfigDict, Field

from ..secret.models import SecretAction, SecretCreate, SecretKind
from ..secret.store import SecretStore
from .models import ActionContext, BrowserProfile
from .store import BrowserWorkerStore


class ConnectorProvider(StrEnum):
    SLACK = "slack"
    GMAIL = "gmail"
    GOOGLE_CALENDAR = "google_calendar"


class ConnectorSendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    conversation_id: str = Field(min_length=1, max_length=512)
    subject: str = Field(default="", max_length=998)
    text: str = Field(min_length=1, max_length=100_000)
    thread_id: str | None = Field(default=None, max_length=512)
    reply_to: str | None = Field(default=None, max_length=512)
    oauth_client_id_credential_id: str | None = Field(
        default=None, pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$"
    )
    oauth_client_secret_credential_id: str | None = Field(
        default=None, pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$"
    )
    context: ActionContext


class ConnectorSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    task_id: str = Field(min_length=1, max_length=128)
    query: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=20, ge=1, le=50)
    oauth_client_id_credential_id: str | None = Field(
        default=None, pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$"
    )
    oauth_client_secret_credential_id: str | None = Field(
        default=None, pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$"
    )


class GoogleCredentialRefs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    client_id_credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    client_secret_credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")


class GoogleCalendarRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credentials: GoogleCredentialRefs
    task_id: str = Field(min_length=1, max_length=128)
    operation: Literal["list", "search", "get", "free_busy", "create", "update", "cancel"]
    calendar_id: str = Field(default="primary", min_length=1, max_length=512)
    event_id: str | None = Field(default=None, max_length=512)
    payload: dict[str, Any] = Field(default_factory=dict)


class GoogleCredentialCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credentials: GoogleCredentialRefs
    task_id: str = Field(min_length=1, max_length=128)


class GoogleOAuthStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=128)
    client_id_credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    client_secret_credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    refresh_credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    redirect_uri: str = Field(min_length=1, max_length=2_000)
    scopes: list[str] = Field(min_length=1, max_length=10)
    account_label: str = Field(min_length=1, max_length=200)


class GoogleOAuthExchangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: str = Field(min_length=32, max_length=512)
    code: str = Field(min_length=1, max_length=8_000)


class GmailAttachmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credentials: GoogleCredentialRefs
    task_id: str = Field(min_length=1, max_length=128)
    message_id: str = Field(min_length=1, max_length=512)
    attachment_id: str = Field(min_length=1, max_length=2_000)
    filename: str = Field(min_length=1, max_length=500)
    media_type: str = Field(default="application/octet-stream", max_length=500)


class ConnectorWorkerService:
    _origins = {
        ConnectorProvider.SLACK: "https://slack.com",
        ConnectorProvider.GMAIL: "https://gmail.googleapis.com",
        ConnectorProvider.GOOGLE_CALENDAR: "https://www.googleapis.com",
    }
    _google_scopes = {
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/contacts.readonly",
    }

    def __init__(
        self,
        secrets: SecretStore,
        store: BrowserWorkerStore,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        quarantine_root: Path = Path("data/browser-downloads"),
    ) -> None:
        self.secrets = secrets
        self.store = store
        self.transport = transport
        self.quarantine_root = quarantine_root.resolve()

    async def send(
        self, provider: ConnectorProvider, request: ConnectorSendRequest
    ) -> dict[str, Any]:
        if provider not in {ConnectorProvider.SLACK, ConnectorProvider.GMAIL}:
            raise ValueError("This provider does not support generic message send")
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
        oauth_refresh = False
        result = "error"
        try:
            oauth_refresh = bool(
                provider is ConnectorProvider.GMAIL
                and request.oauth_client_id_credential_id
                and request.oauth_client_secret_credential_id
            )
            if oauth_refresh:
                token = await self._google_access_token(
                    GoogleCredentialRefs(
                        refresh_credential_id=request.credential_id,
                        client_id_credential_id=request.oauth_client_id_credential_id,
                        client_secret_credential_id=request.oauth_client_secret_credential_id,
                    ),
                    task_id=context.task_id,
                )
            else:
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
            if not oauth_refresh:
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
        if provider not in {ConnectorProvider.SLACK, ConnectorProvider.GMAIL}:
            raise ValueError("This provider does not support generic message search")
        origin = self._origins[provider]
        token = ""
        oauth_refresh = False
        result = "error"
        try:
            oauth_refresh = bool(
                provider is ConnectorProvider.GMAIL
                and request.oauth_client_id_credential_id
                and request.oauth_client_secret_credential_id
            )
            if oauth_refresh:
                token = await self._google_access_token(
                    GoogleCredentialRefs(
                        refresh_credential_id=request.credential_id,
                        client_id_credential_id=request.oauth_client_id_credential_id,
                        client_secret_credential_id=request.oauth_client_secret_credential_id,
                    ),
                    task_id=request.task_id,
                )
            else:
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
            if not oauth_refresh:
                self.secrets.record_use(
                    credential_id=request.credential_id,
                    task_id=request.task_id,
                    origin=origin,
                    action=SecretAction.CONNECTOR_REQUEST,
                    result=result,
                )

    def google_oauth_start(self, request: GoogleOAuthStartRequest) -> dict[str, Any]:
        parsed = urlsplit(request.redirect_uri)
        loopback = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
        if not ((parsed.scheme == "https" and parsed.hostname) or loopback):
            raise ValueError("Google OAuth redirect must be HTTPS or an exact loopback URL")
        scopes = sorted(set(request.scopes))
        if not set(scopes).issubset(self._google_scopes):
            raise PermissionError("Google OAuth request contains a non-allowlisted scope")
        origin = "https://oauth2.googleapis.com"
        client_id = ""
        result = "error"
        try:
            client_id = self.secrets.value_for_use(
                credential_id=request.client_id_credential_id,
                origin=origin,
                action=SecretAction.CONNECTOR_REQUEST,
                task_id=request.task_id,
            )
            state = secrets.token_urlsafe(48)
            session_id = str(uuid4())
            self.store.put_oauth_session(
                session_id=session_id,
                state=state,
                task_id=request.task_id,
                client_id_credential_id=request.client_id_credential_id,
                client_secret_credential_id=request.client_secret_credential_id,
                refresh_credential_id=request.refresh_credential_id,
                redirect_uri=request.redirect_uri,
                scopes=scopes,
                account_label=request.account_label,
            )
            parameters = {
                "client_id": client_id,
                "redirect_uri": request.redirect_uri,
                "response_type": "code",
                "scope": " ".join(scopes),
                "access_type": "offline",
                "include_granted_scopes": "true",
                "prompt": "consent",
                "state": state,
            }
            result = "ok"
            return {
                "status": "authorization_required",
                "authorization_url": (
                    "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(parameters)
                ),
                "session_id": session_id,
                "expires_in": 600,
                "scopes": scopes,
                "secret_values_exposed": False,
            }
        finally:
            client_id = ""
            self.secrets.record_use(
                credential_id=request.client_id_credential_id,
                task_id=request.task_id,
                origin=origin,
                action=SecretAction.CONNECTOR_REQUEST,
                result=result,
            )

    async def google_oauth_exchange(self, request: GoogleOAuthExchangeRequest) -> dict[str, Any]:
        session = self.store.consume_oauth_session(request.state)
        origin = "https://oauth2.googleapis.com"
        values: dict[str, str] = {}
        token_result = "error"
        refresh_token = ""
        code = request.code
        try:
            for key in ("client_id", "client_secret"):
                credential_id = session[f"{key}_credential_id"]
                values[key] = self.secrets.value_for_use(
                    credential_id=credential_id,
                    origin=origin,
                    action=SecretAction.CONNECTOR_REQUEST,
                    task_id=session["task_id"],
                )
            async with httpx.AsyncClient(timeout=30, transport=self.transport) as client:
                response = await client.post(
                    f"{origin}/token",
                    data={
                        **values,
                        "code": code,
                        "redirect_uri": session["redirect_uri"],
                        "grant_type": "authorization_code",
                    },
                )
                response.raise_for_status()
                data = response.json()
            refresh_token = str(data.get("refresh_token") or "")
            if not refresh_token:
                raise RuntimeError("Google did not return an offline refresh token")
            metadata = self.secrets.put(
                SecretCreate(
                    credential_id=session["refresh_credential_id"],
                    kind=SecretKind.API_TOKEN,
                    account_label=session["account_label"],
                    allowed_origins=[origin],
                    allowed_actions=[SecretAction.CONNECTOR_REQUEST],
                ),
                refresh_token,
            )
            token_result = "ok"
            return {
                "status": "connected",
                "task_id": session["task_id"],
                "credential": metadata.model_dump(mode="json"),
                "scopes": session["scopes"],
                "refresh_token_exposed": False,
            }
        finally:
            code = ""
            refresh_token = ""
            values.clear()
            for key in ("client_id", "client_secret"):
                self.secrets.record_use(
                    credential_id=session[f"{key}_credential_id"],
                    task_id=session["task_id"],
                    origin=origin,
                    action=SecretAction.CONNECTOR_REQUEST,
                    result=token_result,
                )

    async def gmail_attachment(self, request: GmailAttachmentRequest) -> dict[str, Any]:
        token = await self._google_access_token(request.credentials, task_id=request.task_id)
        try:
            url = (
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/"
                f"{quote(request.message_id, safe='')}/attachments/"
                f"{quote(request.attachment_id, safe='')}"
            )
            async with httpx.AsyncClient(timeout=60, transport=self.transport) as client:
                response = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                response.raise_for_status()
                encoded = str(response.json().get("data") or "")
            padded = encoded + "=" * (-len(encoded) % 4)
            content = base64.urlsafe_b64decode(padded)
            if len(content) > 50 * 1024 * 1024:
                raise ValueError("Gmail attachment exceeds the 50 MiB quarantine limit")
            safe_name = re.sub(r"[^A-Za-z0-9._() -]+", "_", Path(request.filename).name)
            safe_name = safe_name.strip(" .") or "attachment.bin"
            task_directory = (
                self.quarantine_root / hashlib.sha256(request.task_id.encode()).hexdigest()[:24]
            )
            task_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = task_directory / f"{uuid4()}-{safe_name}"
            with path.open("xb") as target:
                target.write(content)
            try:
                path.chmod(0o600)
            except OSError:
                pass
            executable = path.suffix.casefold() in {
                ".bat",
                ".cmd",
                ".com",
                ".exe",
                ".js",
                ".msi",
                ".ps1",
                ".scr",
                ".vbs",
            }
            return {
                "status": "quarantined",
                "path": str(path),
                "filename": safe_name,
                "media_type": request.media_type,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "executable": executable,
                "executed": False,
                "trust_boundary": "untrusted_external_content",
            }
        finally:
            token = ""

    async def google_calendar(self, request: GoogleCalendarRequest) -> dict[str, Any]:
        token = await self._google_access_token(request.credentials, task_id=request.task_id)
        calendar_id = quote(request.calendar_id, safe="")
        base = f"https://www.googleapis.com/calendar/v3/calendars/{calendar_id}"
        headers = {"Authorization": f"Bearer {token}"}
        operation = request.operation
        try:
            async with httpx.AsyncClient(timeout=30, transport=self.transport) as client:
                if operation in {"list", "search"}:
                    allowed = {
                        "timeMin",
                        "timeMax",
                        "q",
                        "pageToken",
                        "syncToken",
                        "maxResults",
                        "singleEvents",
                        "orderBy",
                    }
                    params = {
                        key: value for key, value in request.payload.items() if key in allowed
                    }
                    response = await client.get(f"{base}/events", headers=headers, params=params)
                elif operation == "get":
                    if not request.event_id:
                        raise ValueError("Google Calendar get requires event_id")
                    response = await client.get(
                        f"{base}/events/{quote(request.event_id, safe='')}", headers=headers
                    )
                elif operation == "free_busy":
                    payload = {
                        "timeMin": request.payload.get("timeMin"),
                        "timeMax": request.payload.get("timeMax"),
                        "timeZone": request.payload.get("timeZone"),
                        "items": [{"id": request.calendar_id}],
                    }
                    response = await client.post(
                        "https://www.googleapis.com/calendar/v3/freeBusy",
                        headers=headers,
                        json=payload,
                    )
                elif operation == "create":
                    response = await client.post(
                        f"{base}/events", headers=headers, json=request.payload
                    )
                elif operation == "update":
                    if not request.event_id:
                        raise ValueError("Google Calendar update requires event_id")
                    response = await client.patch(
                        f"{base}/events/{quote(request.event_id, safe='')}",
                        headers=headers,
                        json=request.payload,
                    )
                else:
                    if not request.event_id:
                        raise ValueError("Google Calendar cancel requires event_id")
                    response = await client.delete(
                        f"{base}/events/{quote(request.event_id, safe='')}", headers=headers
                    )
                response.raise_for_status()
                data = {} if response.status_code == 204 else response.json()
        finally:
            token = ""
            headers.clear()
        self.store.record_audit(
            profile=BrowserProfile.COMMUNICATION,
            task_id=request.task_id,
            actor="connector_worker",
            action=f"connector.google_calendar.{operation}",
            result="ok",
            details={
                "calendar_id": request.calendar_id,
                "event_id": request.event_id,
                "refresh_token_exposed": False,
            },
        )
        return {
            "status": "ok",
            "provider": "google_calendar",
            "operation": operation,
            "data": data,
            "trust_boundary": "untrusted_external_content",
        }

    async def google_status(self, request: GoogleCredentialCheckRequest) -> dict[str, Any]:
        await self._google_access_token(request.credentials, task_id=request.task_id)
        self.store.record_audit(
            profile=BrowserProfile.COMMUNICATION,
            task_id=request.task_id,
            actor="connector_worker",
            action="connector.google.status",
            result="ok",
            details={"access_token_exposed": False, "refresh_token_exposed": False},
        )
        return {
            "status": "ok",
            "refresh_succeeded": True,
            "access_token_exposed": False,
            "refresh_token_exposed": False,
        }

    async def _google_access_token(self, credentials: GoogleCredentialRefs, *, task_id: str) -> str:
        origin = "https://oauth2.googleapis.com"
        refs = {
            "refresh_token": credentials.refresh_credential_id,
            "client_id": credentials.client_id_credential_id,
            "client_secret": credentials.client_secret_credential_id,
        }
        values: dict[str, str] = {}
        result = "error"
        try:
            for key, credential_id in refs.items():
                values[key] = self.secrets.value_for_use(
                    credential_id=credential_id,
                    origin=origin,
                    action=SecretAction.CONNECTOR_REQUEST,
                    task_id=task_id,
                )
            async with httpx.AsyncClient(timeout=20, transport=self.transport) as client:
                response = await client.post(
                    f"{origin}/token",
                    data={**values, "grant_type": "refresh_token"},
                )
                response.raise_for_status()
                data = response.json()
            token = str(data.get("access_token") or "")
            if not token:
                raise RuntimeError("Google OAuth refresh returned no access token")
            result = "ok"
            return token
        finally:
            values.clear()
            for credential_id in refs.values():
                self.secrets.record_use(
                    credential_id=credential_id,
                    task_id=task_id,
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
            verified = False
            if data.get("id"):
                verification = await client.get(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{data['id']}",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"format": "metadata", "metadataHeaders": ["Message-ID"]},
                )
                verification.raise_for_status()
                verified_data = verification.json()
                verified = bool(
                    verified_data.get("id") == data.get("id")
                    and "SENT" in (verified_data.get("labelIds") or [])
                )
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
            "attachments": cls._gmail_attachments(payload),
            "reply_to": headers.get("in-reply-to"),
            "permissions": ["messages.read"],
            "labels": [str(label) for label in item.get("labelIds") or []],
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

    @classmethod
    def _gmail_attachments(cls, payload: dict[str, Any]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        filename = str(payload.get("filename") or "")
        body = payload.get("body") or {}
        attachment_id = body.get("attachmentId")
        if filename and attachment_id:
            result.append(
                {
                    "attachment_id": str(attachment_id),
                    "filename": filename,
                    "media_type": str(payload.get("mimeType") or "application/octet-stream"),
                    "quarantined": True,
                }
            )
        for part in payload.get("parts") or []:
            result.extend(cls._gmail_attachments(part))
        return result

    def _finish(self, idempotency_key: str, result: dict[str, Any]) -> None:
        self.store.finish_action(
            profile=BrowserProfile.COMMUNICATION,
            idempotency_key=idempotency_key,
            result=result,
        )
