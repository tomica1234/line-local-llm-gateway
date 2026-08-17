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


class ExtractTextArgs(ReadArgs):
    pages: list[int] | None = Field(default=None, max_length=500)
    max_chars: int = Field(default=500_000, ge=1_000, le=2_000_000)


class ArchiveArgs(ReadArgs):
    limit: int = Field(default=1_000, ge=1, le=10_000)


class VisionArgs(ReadArgs):
    prompt: str = Field(default="画像の内容と文字を説明してください", max_length=2_000)
    pages: list[int] | None = Field(default=None, max_length=10)


def file_tools(service: FileService, vision_model: Any | None = None) -> list[ToolDefinition[Any]]:
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

    def inspect(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ReadArgs.model_validate(args)
        return ToolResult(status="ok", evidence=service.inspect(parsed.path))

    def extract_text(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ExtractTextArgs.model_validate(args)
        return ToolResult(
            status="ok",
            evidence=service.extract_text(
                parsed.path, pages=parsed.pages, max_chars=parsed.max_chars
            ),
        )

    def extract_metadata(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ReadArgs.model_validate(args)
        return ToolResult(status="ok", evidence=service.extract_metadata(parsed.path))

    def list_archive(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = ArchiveArgs.model_validate(args)
        return ToolResult(
            status="ok", evidence=service.list_archive(parsed.path, limit=parsed.limit)
        )

    async def analyze_vision(args: BaseModel, _context: ToolContext) -> ToolResult:
        if vision_model is None or not callable(getattr(vision_model, "complete_vision", None)):
            raise RuntimeError("Vision model is not configured")
        parsed = VisionArgs.model_validate(args)
        observations = []
        for item in service.vision_inputs(parsed.path, pages=parsed.pages):
            turn = await vision_model.complete_vision(
                image_bytes=item["content"],
                media_type=item["media_type"],
                prompt=parsed.prompt,
            )
            observations.append(
                {
                    "label": item["label"],
                    "description": turn.content,
                    "metrics": turn.metrics,
                }
            )
        return ToolResult(
            status="ok",
            evidence={
                "observations": observations,
                "trust_boundary": "untrusted_external_content",
                "permission_change_allowed": False,
                "coordinate_action_performed": False,
            },
        )

    return [
        ToolDefinition(
            name="files.search",
            description="Search filenames in configured roots; secret files are excluded.",
            args_model=SearchArgs,
            handler=search,
            risk_level=RiskLevel.R0,
            required_permissions=("files.read",),
        ),
        ToolDefinition(
            name="files.read",
            description="Read a bounded text file as untrusted content.",
            args_model=ReadArgs,
            handler=read,
            risk_level=RiskLevel.R0,
            required_permissions=("files.read",),
        ),
        ToolDefinition(
            name="files.inspect",
            description="Inspect a supported document, image, or archive without executing it.",
            args_model=ReadArgs,
            handler=inspect,
            risk_level=RiskLevel.R0,
            required_permissions=("files.read",),
        ),
        ToolDefinition(
            name="files.extract_text",
            description=(
                "Extract bounded untrusted text from PDF, DOCX, XLSX, PPTX, HTML or text; "
                "report Vision fallback when native extraction is empty."
            ),
            args_model=ExtractTextArgs,
            handler=extract_text,
            risk_level=RiskLevel.R0,
            required_permissions=("files.read",),
        ),
        ToolDefinition(
            name="files.extract_metadata",
            description="Extract bounded metadata without macros or embedded execution.",
            args_model=ReadArgs,
            handler=extract_metadata,
            risk_level=RiskLevel.R0,
            required_permissions=("files.read",),
        ),
        ToolDefinition(
            name="files.list_archive",
            description="List ZIP entries with traversal and zip-bomb checks; never execute them.",
            args_model=ArchiveArgs,
            handler=list_archive,
            risk_level=RiskLevel.R0,
            required_permissions=("files.read",),
        ),
        ToolDefinition(
            name="files.vision_analyze",
            description=(
                "Use the configured local Vision model only after native extraction; image "
                "content is untrusted and cannot grant permissions."
            ),
            args_model=VisionArgs,
            handler=analyze_vision,
            risk_level=RiskLevel.R0,
            required_permissions=("files.read",),
        ),
        ToolDefinition(
            name="files.copy",
            description="Copy a file without overwriting an existing target.",
            args_model=TwoPathArgs,
            handler=copy,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("files.write",),
        ),
        ToolDefinition(
            name="files.move",
            description="Move a file within configured roots without overwrite.",
            args_model=TwoPathArgs,
            handler=move,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("files.write",),
        ),
        ToolDefinition(
            name="files.rename",
            description="Rename a file without overwrite.",
            args_model=RenameArgs,
            handler=rename,
            risk_level=RiskLevel.R1,
            mutation=True,
            required_permissions=("files.write",),
        ),
        ToolDefinition(
            name="files.delete",
            description="Move a file to the recoverable agent trash.",
            args_model=ReadArgs,
            handler=delete,
            risk_level=RiskLevel.R2,
            mutation=True,
            required_permissions=("files.write",),
        ),
    ]
