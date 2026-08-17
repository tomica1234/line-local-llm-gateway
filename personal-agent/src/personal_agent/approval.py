from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .redaction import redact


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


class ApprovalMaterial(BaseModel):
    """Human-readable content that a single-use approval is cryptographically bound to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_type: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=500)
    human_summary: str = Field(min_length=1, max_length=4_000)
    structured_payload: dict[str, Any]
    material_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @classmethod
    def create(
        cls,
        *,
        action_type: str,
        title: str,
        human_summary: str,
        structured_payload: dict[str, Any],
    ) -> ApprovalMaterial:
        safe_payload = redact(structured_payload)
        content = {
            "action_type": action_type,
            "title": title,
            "human_summary": human_summary,
            "structured_payload": safe_payload,
        }
        digest = hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()
        return cls(**content, material_hash=digest)

    @model_validator(mode="after")
    def validate_hash(self) -> ApprovalMaterial:
        content = self.model_dump(exclude={"material_hash"}, mode="json")
        digest = hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()
        if digest != self.material_hash:
            raise ValueError("Approval material hash does not match its content")
        return self


def generic_approval_material(tool_name: str, arguments: dict[str, Any]) -> ApprovalMaterial:
    return ApprovalMaterial.create(
        action_type=tool_name,
        title=f"{tool_name} を実行",
        human_summary="表示された内容で操作を1回だけ実行します。",
        structured_payload=arguments,
    )
