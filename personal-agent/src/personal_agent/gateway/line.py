from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

import httpx

from ..audit import AuditLogger
from ..core.service import AgentService
from ..storage import Storage
from ..types import Channel, MessageRequest


def verify_signature(body: bytes, signature: str, channel_secret: str) -> bool:
    digest = hmac.new(channel_secret.encode(), body, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, signature)


def line_source_id(source: dict[str, Any]) -> str | None:
    return source.get("groupId") or source.get("roomId") or source.get("userId")


async def process_line_event(
    *,
    event: dict[str, Any],
    service: AgentService,
    storage: Storage,
    audit: AuditLogger,
    access_token: str,
) -> None:
    reply_token = event.get("replyToken")
    message = event.get("message", {})
    conversation_id = line_source_id(event.get("source", {})) or "line"
    try:
        response = await service.handle_message(
            MessageRequest(
                text=message["text"],
                source=Channel.LINE,
                conversation_id=conversation_id,
            )
        )
        text = response.text
    except Exception as exc:
        text = "処理に失敗しました。Task状態はWeb UIで確認できます。"
        audit.record(
            task_id=None,
            actor="gateway:line",
            action="event.process",
            result="error",
            details={"error_type": type(exc).__name__, "message": str(exc)},
        )

    if not reply_token:
        return
    async with httpx.AsyncClient(timeout=15) as client:
        reply = await client.post(
            "https://api.line.me/v2/bot/message/reply",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json={"replyToken": reply_token, "messages": [{"type": "text", "text": text[:5000]}]},
        )
        if reply.is_error:
            audit.record(
                task_id=None,
                actor="gateway:line",
                action="message.reply",
                result="error",
                details={"status_code": reply.status_code},
            )
