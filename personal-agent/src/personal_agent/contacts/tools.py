from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .store import ContactsStore


class ContactSearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=20, ge=1, le=100)


class ContactIdArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contact_id: str = Field(min_length=1, max_length=128)


class ResolveArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=500)
    destination_kind: str | None = Field(default=None, pattern=r"^(email|phone|line|google)$")


class LinkArgs(ContactIdArgs):
    entity_id: str = Field(min_length=1, max_length=128)


def contact_tools(store: ContactsStore) -> list[ToolDefinition[Any]]:
    def search(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ContactSearchArgs.model_validate(args)
        contacts = store.search(parsed.query, limit=parsed.limit)
        return ToolResult(
            status="ok",
            evidence={"contacts": [item.model_dump(mode="json") for item in contacts]},
        )

    def get(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ContactIdArgs.model_validate(args)
        return ToolResult(
            status="ok",
            evidence=store.get(parsed.contact_id).model_dump(mode="json"),
        )

    def resolve(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ResolveArgs.model_validate(args)
        resolution = store.resolve(parsed.query, destination_kind=parsed.destination_kind)
        return ToolResult(
            status="ok" if resolution.status == "resolved" else "waiting_user",
            evidence=resolution.model_dump(mode="json"),
            next_action=(None if resolution.status == "resolved" else "ask_user_to_choose_contact"),
        )

    def link(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = LinkArgs.model_validate(args)
        contact = store.link_identity(parsed.contact_id, entity_id=parsed.entity_id)
        return ToolResult(status="ok", reversible=True, evidence=contact.model_dump(mode="json"))

    return [
        ToolDefinition(
            name="contacts.search",
            description="Search normalized manual, Google, Gmail, LINE, and memory contacts.",
            args_model=ContactSearchArgs,
            handler=search,
            risk_level=RiskLevel.R0,
            required_permissions=("contacts.read",),
        ),
        ToolDefinition(
            name="contacts.get",
            description="Read one exact contact and its explicit delivery identities.",
            args_model=ContactIdArgs,
            handler=get,
            risk_level=RiskLevel.R0,
            required_permissions=("contacts.read",),
        ),
        ToolDefinition(
            name="contacts.resolve",
            description=(
                "Resolve a name only when one destination has high confidence; otherwise stop "
                "and return human-readable candidates."
            ),
            args_model=ResolveArgs,
            handler=resolve,
            risk_level=RiskLevel.R0,
            required_permissions=("contacts.read",),
        ),
        ToolDefinition(
            name="contacts.link_identity",
            description="Link an exact contact to an existing user-owned memory entity.",
            args_model=LinkArgs,
            handler=link,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("contacts.write",),
        ),
    ]
