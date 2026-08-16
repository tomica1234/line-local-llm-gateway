from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .service import FileService


class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=50, ge=1, le=100)


class ReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=4_096)


class TwoPathArgs(ReadArgs):
    destination: str = Field(min_length=1, max_length=4_096)


class RenameArgs(ReadArgs):
    name: str = Field(min_length=1, max_length=255)


def file_tools(service: FileService) -> list[ToolDefinition[Any]]:
    def search(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = SearchArgs.model_validate(args)
        return ToolResult(
            status="ok",
            evidence={"files": service.search(parsed.query, limit=parsed.limit)},
        )

    def read(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ReadArgs.model_validate(args)
        return ToolResult(status="ok", evidence=service.read(parsed.path))

    def copy(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = TwoPathArgs.model_validate(args)
        return ToolResult(
            status="ok",
            reversible=True,
            evidence=service.copy(parsed.path, parsed.destination),
        )

    def move(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = TwoPathArgs.model_validate(args)
        return ToolResult(
            status="ok",
            reversible=True,
            evidence=service.move(parsed.path, parsed.destination),
        )

    def rename(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = RenameArgs.model_validate(args)
        return ToolResult(
            status="ok",
            reversible=True,
            evidence=service.rename(parsed.path, parsed.name),
        )

    def delete(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ReadArgs.model_validate(args)
        return ToolResult(
            status="ok",
            reversible=True,
            evidence=service.delete_to_trash(parsed.path),
        )

    return [
        ToolDefinition(
            name="files.search",
            description="Search filenames in configured roots; secret files are excluded.",
            args_model=SearchArgs,
            handler=search,
            risk_level=RiskLevel.R0,
        ),
        ToolDefinition(
            name="files.read",
            description="Read a bounded text file as untrusted content.",
            args_model=ReadArgs,
            handler=read,
            risk_level=RiskLevel.R0,
        ),
        ToolDefinition(
            name="files.copy",
            description="Copy a file without overwriting an existing target.",
            args_model=TwoPathArgs,
            handler=copy,
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="files.move",
            description="Move a file within configured roots without overwrite.",
            args_model=TwoPathArgs,
            handler=move,
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="files.rename",
            description="Rename a file without overwrite.",
            args_model=RenameArgs,
            handler=rename,
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="files.delete",
            description="Move a file to the recoverable agent trash.",
            args_model=ReadArgs,
            handler=delete,
            risk_level=RiskLevel.R2,
            mutation=True,
        ),
    ]
