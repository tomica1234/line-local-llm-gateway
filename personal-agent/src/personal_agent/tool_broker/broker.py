from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from ..approval import ApprovalMaterial, generic_approval_material
from ..audit import AuditLogger, redact
from ..policy.engine import PolicyEngine, PolicyOutcome
from ..storage import Storage
from ..types import RiskLevel, ToolResult

ArgsT = TypeVar("ArgsT", bound=BaseModel)
ToolHandler = Callable[[BaseModel, "ToolContext"], ToolResult | Awaitable[ToolResult]]
ApprovalMaterialBuilder = Callable[[BaseModel], ApprovalMaterial]


@dataclass(frozen=True, slots=True)
class ToolContext:
    task_id: str
    action_id: str
    idempotency_key: str
    dry_run: bool
    reason: str
    risk_level: RiskLevel
    step_id: str | None = None
    granted_permissions: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ToolDefinition(Generic[ArgsT]):
    name: str
    description: str
    args_model: type[ArgsT]
    handler: ToolHandler
    risk_level: RiskLevel
    mutation: bool = False
    required_permissions: tuple[str, ...] = ()
    approval_material_builder: ApprovalMaterialBuilder | None = None


class ToolNotAvailable(KeyError):
    pass


class ToolBroker:
    def __init__(self, storage: Storage, policy: PolicyEngine, audit: AuditLogger) -> None:
        self.storage = storage
        self.policy = policy
        self.audit = audit
        self._tools: dict[str, ToolDefinition[Any]] = {}

    def register(self, definition: ToolDefinition[Any]) -> None:
        if definition.name in self._tools:
            raise ValueError(f"Tool already registered: {definition.name}")
        self._tools[definition.name] = definition

    def schemas(
        self,
        allowed_names: set[str] | None = None,
        granted_permissions: set[str] | frozenset[str] | None = None,
    ) -> list[dict[str, Any]]:
        definitions = self._tools.values()
        if allowed_names is not None:
            definitions = [tool for tool in definitions if tool.name in allowed_names]
        if granted_permissions is not None:
            definitions = [
                tool
                for tool in definitions
                if set(tool.required_permissions).issubset(granted_permissions)
            ]
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "risk_level": tool.risk_level.value,
                "mutation": tool.mutation,
                "parameters": tool.args_model.model_json_schema(),
            }
            for tool in definitions
        ]

    def is_mutation(self, tool_name: str) -> bool:
        definition = self._tools.get(tool_name)
        if definition is None:
            raise ToolNotAvailable(tool_name)
        return definition.mutation

    def required_permissions(self, tool_name: str) -> frozenset[str]:
        definition = self._tools.get(tool_name)
        if definition is None:
            raise ToolNotAvailable(tool_name)
        return frozenset(definition.required_permissions)

    async def execute(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        task_id: str,
        idempotency_key: str,
        dry_run: bool,
        reason: str,
        allowed_names: set[str],
        granted_permissions: set[str] | frozenset[str] = frozenset(),
        step_id: str | None = None,
    ) -> ToolResult:
        if tool_name not in self._tools:
            raise ToolNotAvailable(tool_name)
        tool = self._tools[tool_name]
        required = frozenset(tool.required_permissions)
        granted = frozenset(granted_permissions)
        if tool_name not in allowed_names:
            self._record_capability_decision(
                task_id=task_id,
                tool_name=tool_name,
                required=required,
                granted=granted,
                decision="denied",
                reason_code="TOOL_NOT_EXPOSED",
                step_id=step_id,
            )
            return ToolResult(
                status="denied",
                evidence={"reason_code": "TOOL_NOT_EXPOSED"},
            )
        if not required.issubset(granted):
            self._record_capability_decision(
                task_id=task_id,
                tool_name=tool_name,
                required=required,
                granted=granted,
                decision="denied",
                reason_code="PERMISSION_NOT_GRANTED",
                step_id=step_id,
            )
            return ToolResult(
                status="denied",
                evidence={
                    "reason_code": "PERMISSION_NOT_GRANTED",
                    "required_permissions": sorted(required),
                    "granted_permissions": sorted(granted),
                },
            )
        self._record_capability_decision(
            task_id=task_id,
            tool_name=tool_name,
            required=required,
            granted=granted,
            decision="allowed",
            reason_code="CAPABILITY_GRANTED",
            step_id=step_id,
        )
        args = tool.args_model.model_validate(arguments)
        audited_arguments = self._audit_arguments(tool_name, args.model_dump(mode="json"))
        decision = self.policy.evaluate(tool_name=tool_name, risk_level=tool.risk_level)
        self.audit.record(
            task_id=task_id,
            actor="tool_broker",
            action="policy.evaluate",
            result=decision.outcome.value,
            details={
                "tool": tool_name,
                "risk_level": tool.risk_level.value,
                "reason_code": decision.reason_code,
                "policy_version": decision.policy_version,
                "step_id": step_id,
                "required_permissions": sorted(required),
                "granted_permissions": sorted(granted),
                "decision": decision.outcome.value,
            },
        )
        if decision.outcome is PolicyOutcome.DENY:
            return ToolResult(
                status="denied",
                evidence={"reason_code": decision.reason_code},
            )
        if decision.outcome is PolicyOutcome.REQUIRE_APPROVAL:
            raw_arguments = args.model_dump(mode="json")
            material = self._approval_material(tool, args, audited_arguments)
            approval = self.storage.approval_for_action(
                task_id=task_id,
                tool_name=tool_name,
                arguments=raw_arguments,
                material=material,
            )
            if approval is None:
                previous = self.storage.latest_approval_for_request(
                    task_id=task_id,
                    tool_name=tool_name,
                    arguments=raw_arguments,
                )
                changed = bool(
                    previous
                    and previous.get("material_hash")
                    and previous["material_hash"] != material.material_hash
                )
                if changed:
                    self.storage.invalidate_approval(
                        previous["approval_id"], reason_code="APPROVAL_MATERIAL_CHANGED"
                    )
                    self.audit.record(
                        task_id=task_id,
                        actor="tool_broker",
                        action="approval.invalidate",
                        result="denied",
                        details={
                            "approval_id": previous["approval_id"],
                            "tool": tool_name,
                            "reason_code": "APPROVAL_MATERIAL_CHANGED",
                            "old_material_hash": previous["material_hash"],
                            "current_material_hash": material.material_hash,
                        },
                    )
                approval = self.storage.request_approval(
                    task_id=task_id,
                    tool_name=tool_name,
                    arguments=raw_arguments,
                    input_summary=audited_arguments,
                    risk_level=tool.risk_level,
                    reason=reason,
                    material=material,
                )
                if changed:
                    return ToolResult(
                        status="denied",
                        requires_approval=True,
                        evidence={
                            "reason_code": "APPROVAL_MATERIAL_CHANGED",
                            "approval_id": approval["approval_id"],
                            "approval_material": approval["material"],
                        },
                        next_action="request_approval",
                    )
            if approval["state"] == "approved":
                current_material = self._approval_material(tool, args, audited_arguments)
                if current_material.material_hash != approval["material_hash"]:
                    self.storage.invalidate_approval(
                        approval["approval_id"], reason_code="APPROVAL_MATERIAL_CHANGED"
                    )
                    replacement = self.storage.request_approval(
                        task_id=task_id,
                        tool_name=tool_name,
                        arguments=raw_arguments,
                        input_summary=audited_arguments,
                        risk_level=tool.risk_level,
                        reason=reason,
                        material=current_material,
                    )
                    return ToolResult(
                        status="denied",
                        requires_approval=True,
                        evidence={
                            "reason_code": "APPROVAL_MATERIAL_CHANGED",
                            "approval_id": replacement["approval_id"],
                            "approval_material": replacement["material"],
                        },
                        next_action="request_approval",
                    )
                if not self.storage.consume_approval(
                    approval["approval_id"],
                    expected_material_hash=current_material.material_hash,
                ):
                    return ToolResult(
                        status="denied",
                        evidence={"reason_code": "APPROVAL_CONSUME_CONFLICT"},
                    )
                self.audit.record(
                    task_id=task_id,
                    actor="tool_broker",
                    action="approval.consume",
                    result="ok",
                    details={"approval_id": approval["approval_id"], "tool": tool_name},
                )
            else:
                reason_code = (
                    decision.reason_code
                    if approval["state"] == "pending"
                    else "APPROVAL_DENIED"
                    if approval["state"] == "denied"
                    else "APPROVAL_ALREADY_CONSUMED"
                )
                return ToolResult(
                    status="denied",
                    requires_approval=approval["state"] == "pending",
                    evidence={
                        "reason_code": reason_code,
                        "approval_id": approval["approval_id"],
                        "approval_material": approval["material"],
                    },
                    next_action=("request_approval" if approval["state"] == "pending" else None),
                )

        action_id, previous = self.storage.begin_action(
            task_id=task_id,
            tool_name=tool_name,
            idempotency_key=idempotency_key,
            dry_run=dry_run,
            risk_level=tool.risk_level,
            reason=reason,
            input_data=audited_arguments,
            step_id=step_id,
            mutation=tool.mutation,
        )
        if previous is not None:
            duplicate = ToolResult.model_validate(previous)
            if duplicate.status == "submitted_unknown":
                duplicate.warnings.append("IDEMPOTENT_REPLAY_SUPPRESSED_PENDING_RECONCILIATION")
                return duplicate
            duplicate.status = "duplicate"
            return duplicate

        context = ToolContext(
            task_id=task_id,
            action_id=action_id,
            idempotency_key=idempotency_key,
            dry_run=dry_run,
            reason=reason,
            risk_level=tool.risk_level,
            step_id=step_id,
            granted_permissions=granted,
        )
        if dry_run and tool.mutation:
            result = ToolResult(
                status="dry_run",
                evidence={"validated_arguments": redact(args.model_dump(mode="json"))},
            )
        else:
            started_at = time.perf_counter()
            try:
                maybe_result = tool.handler(args, context)
                result = await maybe_result if inspect.isawaitable(maybe_result) else maybe_result
            except Exception as exc:
                result = ToolResult(
                    status="error",
                    warnings=[type(exc).__name__],
                    evidence={"message": str(exc)},
                )
            duration_ms = round((time.perf_counter() - started_at) * 1_000, 2)

        result = ToolResult.model_validate(redact(result.model_dump(mode="json")))

        self.storage.finish_action(
            action_id, status=result.status, result=result.model_dump(mode="json")
        )
        self.audit.record(
            task_id=task_id,
            actor="tool_broker",
            action=tool_name,
            result=result.status,
            details={
                "action_id": action_id,
                "input": audited_arguments,
                "output": result.model_dump(mode="json"),
                "reason": reason,
                "duration_ms": duration_ms if not (dry_run and tool.mutation) else 0,
                "step_id": step_id,
                "required_permissions": sorted(required),
                "granted_permissions": sorted(granted),
                "decision": "executed",
            },
        )
        return result

    @staticmethod
    def _approval_material(
        tool: ToolDefinition[Any], args: BaseModel, audited_arguments: dict[str, Any]
    ) -> ApprovalMaterial:
        if tool.approval_material_builder is not None:
            return tool.approval_material_builder(args)
        return generic_approval_material(tool.name, audited_arguments)

    def _record_capability_decision(
        self,
        *,
        task_id: str,
        tool_name: str,
        required: frozenset[str],
        granted: frozenset[str],
        decision: str,
        reason_code: str,
        step_id: str | None,
    ) -> None:
        self.audit.record(
            task_id=task_id,
            actor="tool_broker",
            action="capability.evaluate",
            result=decision,
            details={
                "tool": tool_name,
                "required_permissions": sorted(required),
                "granted_permissions": sorted(granted),
                "decision": decision,
                "reason_code": reason_code,
                "step_id": step_id,
            },
        )

    @staticmethod
    def _audit_arguments(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        safe = redact(arguments)
        if (
            tool_name
            in {
                "browser.type",
                "computer.clipboard.write",
                "computer.desktop.type",
            }
            and "text" in safe
        ):
            safe["text"] = f"[REDACTED:{len(str(arguments['text']))} chars]"
        if tool_name == "browser.upload" and "paths" in safe:
            paths = arguments.get("paths", [])
            safe["paths"] = f"[REDACTED:{len(paths)} paths]"
        return safe
