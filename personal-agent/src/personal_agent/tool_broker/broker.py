from __future__ import annotations

import inspect
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from ..audit import AuditLogger, redact
from ..policy.engine import PolicyEngine, PolicyOutcome
from ..storage import Storage
from ..types import RiskLevel, ToolResult

ArgsT = TypeVar("ArgsT", bound=BaseModel)
ToolHandler = Callable[[BaseModel, "ToolContext"], ToolResult | Awaitable[ToolResult]]


@dataclass(frozen=True, slots=True)
class ToolContext:
    task_id: str
    action_id: str
    idempotency_key: str
    dry_run: bool
    reason: str
    risk_level: RiskLevel


@dataclass(frozen=True, slots=True)
class ToolDefinition(Generic[ArgsT]):
    name: str
    description: str
    args_model: type[ArgsT]
    handler: ToolHandler
    risk_level: RiskLevel
    mutation: bool = False
    required_permissions: tuple[str, ...] = ()


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

    def schemas(self, allowed_names: set[str] | None = None) -> list[dict[str, Any]]:
        definitions = self._tools.values()
        if allowed_names is not None:
            definitions = [tool for tool in definitions if tool.name in allowed_names]
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
    ) -> ToolResult:
        if tool_name not in allowed_names or tool_name not in self._tools:
            raise ToolNotAvailable(tool_name)
        tool = self._tools[tool_name]
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
            },
        )
        if decision.outcome is PolicyOutcome.DENY:
            return ToolResult(
                status="denied",
                evidence={"reason_code": decision.reason_code},
            )
        if decision.outcome is PolicyOutcome.REQUIRE_APPROVAL:
            raw_arguments = args.model_dump(mode="json")
            approval = self.storage.approval_for_action(
                task_id=task_id,
                tool_name=tool_name,
                arguments=raw_arguments,
            )
            if approval is None:
                approval = self.storage.request_approval(
                    task_id=task_id,
                    tool_name=tool_name,
                    arguments=raw_arguments,
                    input_summary=audited_arguments,
                    risk_level=tool.risk_level,
                    reason=reason,
                )
            if approval["state"] == "approved":
                if not self.storage.consume_approval(approval["approval_id"]):
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
            },
        )
        return result

    @staticmethod
    def _audit_arguments(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        safe = redact(arguments)
        if tool_name == "browser.type" and "text" in safe:
            safe["text"] = f"[REDACTED:{len(str(arguments['text']))} chars]"
        if tool_name == "browser.upload" and "paths" in safe:
            paths = arguments.get("paths", [])
            safe["paths"] = f"[REDACTED:{len(paths)} paths]"
        return safe
