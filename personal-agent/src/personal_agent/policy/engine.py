from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..storage import Storage
from ..types import RiskLevel


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    outcome: PolicyOutcome
    reason_code: str
    policy_version: int


class PolicyEngine:
    """A deterministic safety boundary. Model output is never an input here."""

    def __init__(self, storage: Storage):
        self.storage = storage

    def evaluate(self, *, tool_name: str, risk_level: RiskLevel) -> PolicyDecision:
        version = int(self.storage.get_setting("policy_version"))
        global_pause = bool(self.storage.get_setting("global_pause"))
        if global_pause and tool_name not in {"system.status", "task.cancel"}:
            return PolicyDecision(PolicyOutcome.DENY, "GLOBAL_PAUSE_ENABLED", version)

        if tool_name.startswith(("money.", "economic.")) and bool(
            self.storage.get_setting("finance_lock")
        ):
            return PolicyDecision(PolicyOutcome.DENY, "FINANCE_LOCK_ENABLED", version)

        if tool_name.startswith(("browser.", "auth.")) and bool(
            self.storage.get_setting("browser_lock")
        ):
            return PolicyDecision(PolicyOutcome.DENY, "BROWSER_LOCK_ENABLED", version)

        if tool_name.startswith(("auth.", "secret.")) and bool(
            self.storage.get_setting("secret_lock")
        ):
            return PolicyDecision(PolicyOutcome.DENY, "SECRET_LOCK_ENABLED", version)

        if risk_level in {RiskLevel.R0, RiskLevel.R1}:
            return PolicyDecision(PolicyOutcome.ALLOW, "LOW_RISK_AUTO", version)
        if risk_level in {RiskLevel.R2, RiskLevel.R3, RiskLevel.R4}:
            return PolicyDecision(
                PolicyOutcome.REQUIRE_APPROVAL,
                f"{risk_level.value}_APPROVAL_REQUIRED",
                version,
            )
        return PolicyDecision(PolicyOutcome.DENY, "R5_STRONG_AUTH_REQUIRED", version)
