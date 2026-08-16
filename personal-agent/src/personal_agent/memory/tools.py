from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .models import MemoryCreate, MemoryKind
from .store import MemoryStore


class MemoryRememberArgs(BaseModel):
    statement: str = Field(min_length=1, max_length=20_000)
    kind: MemoryKind = MemoryKind.FACT
    confidence: float = Field(default=1.0, ge=0, le=1)
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=100)


class MemoryForgetArgs(BaseModel):
    query: str = Field(min_length=1, max_length=2_000)


class MemorySearchArgs(BaseModel):
    query: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=10, ge=1, le=50)


def memory_tools(memory: MemoryStore, *, user_id: str) -> list[ToolDefinition[Any]]:
    def remember(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = MemoryRememberArgs.model_validate(args.model_dump())
        result = memory.remember(
            user_id=user_id,
            memory=MemoryCreate(
                statement=parsed.statement,
                kind=parsed.kind,
                confidence=parsed.confidence,
                evidence_event_ids=parsed.evidence_event_ids,
            ),
        )
        return ToolResult(
            status="ok",
            external_id=result.memory_id,
            reversible=True,
            evidence={"memory": result.model_dump(mode="json")},
        )

    def forget(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = MemoryForgetArgs.model_validate(args.model_dump())
        deleted = memory.forget(user_id=user_id, query=parsed.query)
        return ToolResult(
            status="ok",
            reversible=False,
            evidence={"deleted_memory_ids": deleted, "count": len(deleted)},
        )

    def search(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = MemorySearchArgs.model_validate(args.model_dump())
        hits = memory.personal_search(user_id=user_id, query=parsed.query, limit=parsed.limit)
        return ToolResult(
            status="ok",
            evidence={"hits": [hit.model_dump(mode="json") for hit in hits]},
        )

    return [
        ToolDefinition(
            name="memory.remember",
            description="Store an explicit user-approved long-term memory with evidence.",
            args_model=MemoryRememberArgs,
            handler=remember,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("memory.write",),
        ),
        ToolDefinition(
            name="memory.forget",
            description="Forget long-term memories matching the user's explicit query.",
            args_model=MemoryForgetArgs,
            handler=forget,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("memory.delete",),
        ),
        ToolDefinition(
            name="memory.search",
            description="Search normalized events and long-term personal memories.",
            args_model=MemorySearchArgs,
            handler=search,
            risk_level=RiskLevel.R0,
            required_permissions=("memory.read",),
        ),
    ]
