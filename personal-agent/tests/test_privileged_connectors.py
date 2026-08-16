from __future__ import annotations

import base64
from email import policy
from email.parser import BytesParser
from pathlib import Path

import httpx
import pytest

from personal_agent.browser_worker.connectors import (
    ConnectorProvider,
    ConnectorSearchRequest,
    ConnectorSendRequest,
    ConnectorWorkerService,
)
from personal_agent.browser_worker.models import ActionContext
from personal_agent.browser_worker.store import BrowserWorkerStore
from personal_agent.secret.models import SecretAction, SecretCreate, SecretKind
from personal_agent.secret.store import SecretStore
from personal_agent.types import RiskLevel


class ReversingProtector:
    name = "test-reversing"

    def protect(self, plaintext: bytes) -> bytes:
        return plaintext[::-1]

    def unprotect(self, ciphertext: bytes) -> bytes:
        return ciphertext[::-1]


def _secret(tmp_path: Path, *, credential_id: str, origin: str, value: str) -> SecretStore:
    store = SecretStore(tmp_path / "secrets.sqlite3", ReversingProtector())
    store.initialize()
    store.put(
        SecretCreate(
            credential_id=credential_id,
            kind=SecretKind.API_TOKEN,
            account_label="test",
            allowed_origins=[origin],
            allowed_actions=[SecretAction.CONNECTOR_REQUEST],
        ),
        value,
    )
    return store


def _context(key: str) -> ActionContext:
    return ActionContext(
        task_id="task-connector",
        action_id="action-connector",
        idempotency_key=key,
        reason="test connector",
        risk_level=RiskLevel.R2,
    )


@pytest.mark.asyncio
async def test_slack_connector_keeps_token_in_worker_and_is_idempotent(
    tmp_path: Path,
) -> None:
    credential_id = "secret://connector/slack/main"
    token = "xoxp-never-return-this"
    secrets = _secret(
        tmp_path, credential_id=credential_id, origin="https://slack.com", value=token
    )
    worker_store = BrowserWorkerStore(tmp_path / "worker.sqlite3")
    worker_store.initialize()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("chat.postMessage"):
            return httpx.Response(
                200,
                json={"ok": True, "channel": "D12345678", "ts": "1700000000.123456"},
            )
        return httpx.Response(
            200,
            json={
                "ok": True,
                "messages": {
                    "matches": [
                        {
                            "iid": "message-1",
                            "channel": {"id": "C12345678"},
                            "text": "見積もりを確認",
                            "ts": "1700000000.123456",
                            "permalink": "https://workspace.slack.com/archives/C123/p1",
                        }
                    ]
                },
            },
        )

    service = ConnectorWorkerService(secrets, worker_store, transport=httpx.MockTransport(handler))
    request = ConnectorSendRequest(
        credential_id=credential_id,
        conversation_id="D12345678",
        text="確認しました",
        context=_context("slack-idempotency-1"),
    )
    first = await service.send(ConnectorProvider.SLACK, request)
    duplicate = await service.send(ConnectorProvider.SLACK, request)
    searched = await service.search(
        ConnectorProvider.SLACK,
        ConnectorSearchRequest(
            credential_id=credential_id,
            task_id="task-search",
            query="見積もり",
            limit=10,
        ),
    )

    assert first["verified"] is True
    assert duplicate["status"] == "duplicate"
    assert len([item for item in requests if item.method == "POST"]) == 1
    assert requests[0].headers["Authorization"] == f"Bearer {token}"
    assert searched["messages"][0]["source"] == "slack"
    assert token not in str(first) + str(duplicate) + str(searched)
    assert [item["result"] for item in secrets.usage()] == ["ok", "ok"]


@pytest.mark.asyncio
async def test_gmail_connector_sends_rfc_message_and_normalizes_search(
    tmp_path: Path,
) -> None:
    credential_id = "secret://connector/gmail/main"
    token = "gmail-oauth-never-return"
    secrets = _secret(
        tmp_path,
        credential_id=credential_id,
        origin="https://gmail.googleapis.com",
        value=token,
    )
    worker_store = BrowserWorkerStore(tmp_path / "worker.sqlite3")
    worker_store.initialize()
    sent_message = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal sent_message
        if request.method == "POST":
            raw = request.read().decode()
            encoded = __import__("json").loads(raw)["raw"]
            padded = encoded + "=" * (-len(encoded) % 4)
            sent_message = BytesParser(policy=policy.default).parsebytes(
                base64.urlsafe_b64decode(padded)
            )
            return httpx.Response(200, json={"id": "gmail-sent-1", "threadId": "t-1"})
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json={"messages": [{"id": "gmail-read-1"}]})
        body = base64.urlsafe_b64encode("返金を確認しました".encode()).decode().rstrip("=")
        return httpx.Response(
            200,
            json={
                "id": "gmail-read-1",
                "threadId": "thread-read-1",
                "internalDate": "1700000000000",
                "payload": {
                    "mimeType": "text/plain",
                    "headers": [{"name": "From", "value": "sender@example.com"}],
                    "body": {"data": body},
                },
            },
        )

    service = ConnectorWorkerService(secrets, worker_store, transport=httpx.MockTransport(handler))
    sent = await service.send(
        ConnectorProvider.GMAIL,
        ConnectorSendRequest(
            credential_id=credential_id,
            conversation_id="person@example.com",
            subject="確認事項",
            text="本文です",
            context=_context("gmail-idempotency-1"),
        ),
    )
    searched = await service.search(
        ConnectorProvider.GMAIL,
        ConnectorSearchRequest(
            credential_id=credential_id,
            task_id="task-gmail-search",
            query="返金",
            limit=10,
        ),
    )

    assert sent["external_message_id"] == "gmail-sent-1"
    assert sent_message["To"] == "person@example.com"
    assert sent_message["Subject"] == "確認事項"
    assert "本文です" in sent_message.get_content()
    normalized = searched["messages"][0]
    assert normalized["source"] == "email"
    assert normalized["text"] == "返金を確認しました"
    assert token not in str(sent) + str(searched)


@pytest.mark.asyncio
async def test_connector_rejects_display_names_and_marks_network_unknown(
    tmp_path: Path,
) -> None:
    credential_id = "secret://connector/slack/main"
    secrets = _secret(
        tmp_path,
        credential_id=credential_id,
        origin="https://slack.com",
        value="token",
    )
    worker_store = BrowserWorkerStore(tmp_path / "worker.sqlite3")
    worker_store.initialize()
    service = ConnectorWorkerService(
        secrets,
        worker_store,
        transport=httpx.MockTransport(
            lambda _request: (_ for _ in ()).throw(httpx.ConnectError("offline"))
        ),
    )
    invalid = await service.send(
        ConnectorProvider.SLACK,
        ConnectorSendRequest(
            credential_id=credential_id,
            conversation_id="general",
            text="not sent",
            context=_context("slack-invalid-id"),
        ),
    )
    unknown = await service.send(
        ConnectorProvider.SLACK,
        ConnectorSendRequest(
            credential_id=credential_id,
            conversation_id="D12345678",
            text="maybe sent",
            context=_context("slack-network-id"),
        ).model_copy(
            update={
                "context": _context("slack-network-id").model_copy(
                    update={"action_id": "action-network"}
                )
            }
        ),
    )
    assert invalid["status"] == "error"
    assert unknown["status"] == "submitted_unknown"
    assert unknown["resent"] is False

    replay = await service.send(
        ConnectorProvider.SLACK,
        ConnectorSendRequest(
            credential_id=credential_id,
            conversation_id="D12345678",
            text="maybe sent",
            context=_context("slack-network-id").model_copy(update={"action_id": "action-network"}),
        ),
    )
    assert replay["status"] == "submitted_unknown"
    assert replay["replay_suppressed"] is True
    assert replay["resent"] is False
