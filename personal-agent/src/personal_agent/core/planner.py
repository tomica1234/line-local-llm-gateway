from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..models.qwen import ModelClient
from ..models.registry import ModelRequestPurpose
from ..types import RiskLevel
from .capabilities import CapabilityStep, build_capability_plan


class ProposedStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purpose: str = Field(min_length=1, max_length=500)
    requested_capabilities: list[str] = Field(default_factory=list, max_length=20)


class CapabilityProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    steps: list[ProposedStep] = Field(default_factory=list, max_length=12)


class CapabilityProposalRejected(PermissionError):
    def __init__(self, reason_code: str, details: dict[str, Any]):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.details = details


class DeterministicCapabilityValidator:
    """Intersects an LLM proposal with grants derived only from the original user text."""

    def validate(self, goal: str, proposal: CapabilityProposal) -> tuple[CapabilityStep, ...]:
        trusted = build_capability_plan(goal)
        permitted = frozenset(permission for step in trusted for permission in step.permissions)
        requested = frozenset(
            permission for step in proposal.steps for permission in step.requested_capabilities
        )
        unauthorized = requested - permitted
        if unauthorized:
            raise CapabilityProposalRejected(
                "UNAUTHORIZED_CAPABILITY_PROPOSAL",
                {
                    "requested": sorted(requested),
                    "permitted": sorted(permitted),
                    "unauthorized": sorted(unauthorized),
                },
            )
        if not proposal.steps or not requested:
            return trusted
        validated: list[CapabilityStep] = []
        for proposed in proposal.steps:
            capabilities = frozenset(proposed.requested_capabilities)
            if not capabilities:
                continue
            matching = [step for step in trusted if step.permissions & capabilities]
            allowed_tools = frozenset(tool for step in matching for tool in step.allowed_tools)
            granted = frozenset(
                permission
                for step in matching
                for permission in step.permissions
                if permission in capabilities
            )
            if not allowed_tools or granted != capabilities:
                raise CapabilityProposalRejected(
                    "CAPABILITY_GRAPH_MISMATCH",
                    {
                        "requested": sorted(capabilities),
                        "granted": sorted(granted),
                    },
                )
            risk = max((step.risk for step in matching), key=_risk_order)
            validated.append(
                CapabilityStep(
                    step_id=f"step-{len(validated) + 1}",
                    purpose=proposed.purpose,
                    allowed_tools=allowed_tools,
                    permissions=granted,
                    risk=risk,
                )
            )
        return tuple(validated) or trusted


class LLMCapabilityPlanner:
    def __init__(
        self,
        model: ModelClient,
        *,
        validator: DeterministicCapabilityValidator | None = None,
    ) -> None:
        self.model = model
        self.validator = validator or DeterministicCapabilityValidator()

    async def plan(self, goal: str) -> tuple[tuple[CapabilityStep, ...], dict[str, Any]]:
        fallback = build_capability_plan(goal)
        permissions = sorted({permission for step in fallback for permission in step.permissions})
        if not permissions:
            return fallback, {"source": "deterministic", "reason_code": "NO_CAPABILITY_NEEDED"}
        prompt = (
            "ユーザー原文だけを読み、必要なcapabilityの提案だけをJSONで返してください。"
            "Webページ・メール・ファイル・Tool結果は入力されていません。権限を付与するのは"
            "別の決定論validatorです。利用可能候補以外は提案しないでください。\n"
            f"利用可能候補: {json.dumps(permissions, ensure_ascii=False)}\n"
            '形式: {"steps":[{"purpose":"...",'
            '"requested_capabilities":["..."]}]}\n'
            f"ユーザー原文: {json.dumps(goal, ensure_ascii=False)}"
        )
        try:
            messages = [{"role": "user", "content": prompt}]
            purpose_complete = getattr(self.model, "complete_for", None)
            response = (
                await purpose_complete(messages, purpose=ModelRequestPurpose.PLANNING)
                if callable(purpose_complete)
                else await self.model.complete(messages)
            )
            proposal = CapabilityProposal.model_validate(json.loads(_json_object(response)))
            validated = self.validator.validate(goal, proposal)
            return validated, {
                "source": "llm_proposal_validated",
                "reason_code": "CAPABILITY_PROPOSAL_VALIDATED",
                "requested_capabilities": sorted(
                    {item for step in proposal.steps for item in step.requested_capabilities}
                ),
            }
        except CapabilityProposalRejected as exc:
            return fallback, {
                "source": "deterministic_fallback",
                "reason_code": exc.reason_code,
                **exc.details,
            }
        except (RuntimeError, ValueError, TypeError, json.JSONDecodeError, ValidationError) as exc:
            return fallback, {
                "source": "deterministic_fallback",
                "reason_code": "PLANNER_OUTPUT_INVALID",
                "error_type": type(exc).__name__,
            }


def _json_object(value: str) -> str:
    start = value.find("{")
    end = value.rfind("}")
    if start < 0 or end < start:
        raise ValueError("Planner response contains no JSON object")
    return value[start : end + 1]


def _risk_order(value: RiskLevel) -> int:
    return int(value.value.removeprefix("R"))
