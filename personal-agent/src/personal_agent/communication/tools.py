from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..approval import ApprovalMaterial
from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .models import CommunicationSource, DraftCreate
from .service import CommunicationService


class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=20, ge=1, le=50)


class ReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: CommunicationSource
    message_id: str = Field(min_length=1, max_length=512)


class ThreadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: CommunicationSource
    conversation_id: str = Field(min_length=1, max_length=512)
    thread_id: str | None = Field(default=None, max_length=512)
    limit: int = Field(default=50, ge=1, le=100)


class DraftArgs(DraftCreate):
    pass


class SendArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    draft_id: str = Field(min_length=1, max_length=128)


class SyncArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: CommunicationSource
    query: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=20, ge=1, le=50)


def communication_tools(service: CommunicationService) -> list[ToolDefinition[Any]]:
    def send_material(args: BaseModel) -> ApprovalMaterial:
        parsed = SendArgs.model_validate(args)
        try:
            draft = service.store.get_draft(parsed.draft_id)
        except KeyError:
            return ApprovalMaterial.create(
                action_type="communication.send",
                title="送信できない下書き",
                human_summary=(
                    "指定された下書きは現在存在しません。承認しても送信処理は実行できません。"
                ),
                structured_payload={
                    "draft_id": parsed.draft_id,
                    "draft_status": "missing",
                    "actual_destination": None,
                    "body": None,
                },
            )
        payload = {
            "provider": draft.source.value,
            "recipient_entity": draft.recipient_entity_id,
            "actual_destination": draft.conversation_id,
            "subject": draft.subject,
            "body": draft.text,
            "thread": draft.thread_id,
            "reply_target": draft.reply_to,
            "attachments": [item.model_dump(mode="json") for item in draft.attachments],
        }
        return ApprovalMaterial.create(
            action_type="communication.send",
            title=f"{draft.source.value}でメッセージを送信",
            human_summary=(f"宛先 {draft.conversation_id} へ、表示された本文を1回だけ送信します。"),
            structured_payload=payload,
        )

    def search(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = SearchArgs.model_validate(args)
        hits = service.store.search(parsed.query, limit=parsed.limit)
        return ToolResult(
            status="ok",
            evidence={
                "trust_boundary": "untrusted_external_content",
                "messages": [item.model_dump(mode="json") for item in hits],
            },
        )

    def read(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ReadArgs.model_validate(args)
        message = service.store.read(source=parsed.source, message_id=parsed.message_id)
        return ToolResult(
            status="ok",
            evidence={
                "trust_boundary": "untrusted_external_content",
                "message": message.model_dump(mode="json"),
            },
        )

    def thread(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ThreadArgs.model_validate(args)
        messages = service.store.thread(
            source=parsed.source,
            conversation_id=parsed.conversation_id,
            thread_id=parsed.thread_id,
            limit=parsed.limit,
        )
        return ToolResult(
            status="ok",
            evidence={
                "trust_boundary": "untrusted_external_content",
                "messages": [item.model_dump(mode="json") for item in messages],
            },
        )

    def draft(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = DraftArgs.model_validate(args)
        record = service.draft(
            task_id=context.task_id,
            draft=DraftCreate.model_validate(parsed.model_dump()),
        )
        return ToolResult(
            status="ok",
            external_id=record.draft_id,
            reversible=True,
            evidence={"draft": record.model_dump(mode="json"), "sent": False},
        )

    async def send(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = SendArgs.model_validate(args)
        record = await service.send(
            draft_id=parsed.draft_id,
            idempotency_key=context.idempotency_key,
            action_id=context.action_id,
        )
        return ToolResult(
            status="submitted_unknown" if record.state == "submitted_unknown" else "ok",
            external_id=record.external_message_id,
            evidence={
                "draft_id": record.draft_id,
                "verified": record.state == "sent",
                "resent": False,
            },
            next_action=(
                "provider_reconciliation" if record.state == "submitted_unknown" else None
            ),
        )

    async def sync(args: BaseModel, context: ToolContext) -> ToolResult:
        parsed = SyncArgs.model_validate(args)
        if parsed.source not in {
            CommunicationSource.SLACK,
            CommunicationSource.EMAIL,
            CommunicationSource.LINE_DESKTOP,
        }:
            raise ValueError("External search sync does not support this source")
        result = await service.sync(
            source=parsed.source,
            task_id=context.task_id,
            query=parsed.query,
            limit=parsed.limit,
        )
        return ToolResult(status="ok", reversible=True, evidence=result)

    return [
        ToolDefinition(
            name="communication.search",
            description="Search normalized LINE, Slack, email, and SMS messages.",
            args_model=SearchArgs,
            handler=search,
            risk_level=RiskLevel.R0,
            required_permissions=("messages.read",),
        ),
        ToolDefinition(
            name="communication.read",
            description="Read one normalized external message by source and immutable ID.",
            args_model=ReadArgs,
            handler=read,
            risk_level=RiskLevel.R0,
            required_permissions=("messages.read",),
        ),
        ToolDefinition(
            name="communication.thread",
            description="Read a bounded message thread in chronological order.",
            args_model=ThreadArgs,
            handler=thread,
            risk_level=RiskLevel.R0,
            required_permissions=("messages.read",),
        ),
        ToolDefinition(
            name="communication.draft",
            description=(
                "Create an unsent reply draft for an exact recipient entity ID; display names "
                "are not accepted."
            ),
            args_model=DraftArgs,
            handler=draft,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("messages.draft",),
        ),
        ToolDefinition(
            name="communication.send",
            description="Send one existing draft after policy approval and provider verification.",
            args_model=SendArgs,
            handler=send,
            risk_level=RiskLevel.R2,
            mutation=True,
            required_permissions=("messages.write",),
            approval_material_builder=send_material,
        ),
        ToolDefinition(
            name="communication.sync",
            description=(
                "Fetch a bounded Slack, Gmail, or read-only LINE Desktop query through a "
                "privileged connector worker and cache normalized untrusted messages locally."
            ),
            args_model=SyncArgs,
            handler=sync,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("messages.read",),
        ),
    ]
