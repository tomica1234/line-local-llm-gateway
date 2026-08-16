from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

from ..core.service import AgentService
from ..storage import Storage, utc_now
from ..types import MessageRequest
from .models import (
    BenchmarkCase,
    BenchmarkCategory,
    BenchmarkReport,
    BenchmarkTrial,
)

BENCHMARK_SCHEMA = """
CREATE TABLE IF NOT EXISTS benchmark_runs (
    run_id TEXT PRIMARY KEY,
    suite_version TEXT NOT NULL,
    report_json TEXT NOT NULL,
    overall_score REAL NOT NULL,
    policy_violations INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""


def load_default_suite() -> tuple[str, list[BenchmarkCase]]:
    resource = files("personal_agent.evaluation").joinpath("suite.json")
    payload = json.loads(resource.read_text(encoding="utf-8"))
    return str(payload["version"]), [
        BenchmarkCase.model_validate(item) for item in payload["cases"]
    ]


class BenchmarkStore:
    def __init__(self, storage: Storage):
        self.storage = storage

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(BENCHMARK_SCHEMA)

    def save(self, report: BenchmarkReport) -> None:
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO benchmark_runs "
                "(run_id, suite_version, report_json, overall_score, "
                "policy_violations, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    report.run_id,
                    report.suite_version,
                    report.model_dump_json(),
                    report.overall_score,
                    report.policy_violations,
                    utc_now(),
                ),
            )

    def list(self, *, limit: int = 20) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT run_id, suite_version, overall_score, policy_violations, "
                "created_at FROM benchmark_runs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, run_id: str) -> BenchmarkReport:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT report_json FROM benchmark_runs WHERE run_id=?", (run_id,)
            ).fetchone()
        if row is None:
            raise KeyError(run_id)
        return BenchmarkReport.model_validate_json(row["report_json"])


class BenchmarkRunner:
    def __init__(
        self,
        service: AgentService,
        storage: Storage,
        store: BenchmarkStore,
        *,
        capabilities: set[str],
    ) -> None:
        self.service = service
        self.storage = storage
        self.store = store
        self.capabilities = capabilities

    async def run(
        self,
        cases: list[BenchmarkCase],
        *,
        suite_version: str,
        trials: int,
    ) -> BenchmarkReport:
        started = datetime.now(UTC)
        run_id = str(uuid.uuid4())
        results: list[BenchmarkTrial] = []
        skipped = 0
        for case in cases:
            missing = sorted(set(case.required_capabilities) - self.capabilities)
            if missing:
                skipped += 1
                results.append(
                    BenchmarkTrial(
                        case_id=case.case_id,
                        category=case.category,
                        trial=0,
                        status="skipped",
                        passed=False,
                        failure=f"Missing capabilities: {', '.join(missing)}",
                    )
                )
                continue
            for trial in range(1, trials + 1):
                results.append(await self._execute(run_id, case, trial))
        report = self._report(
            run_id=run_id,
            suite_version=suite_version,
            started_at=started,
            trials=trials,
            total_cases=len(cases),
            skipped_cases=skipped,
            results=results,
        )
        self.store.save(report)
        return report

    async def _execute(self, run_id: str, case: BenchmarkCase, trial: int) -> BenchmarkTrial:
        started = time.perf_counter()
        try:
            response = await self.service.handle_message(
                MessageRequest(
                    text=case.prompt,
                    source=case.source,
                    conversation_id=f"benchmark:{run_id}:{case.case_id}:{trial}",
                    dry_run=True,
                )
            )
            latency_ms = round((time.perf_counter() - started) * 1_000, 2)
            task = self.storage.get_task(response.task_id)
            evidence = (task.result or {}).get("evidence", {})
            tool_results = evidence.get("tool_results", [])
            if not isinstance(tool_results, list):
                tool_results = []
            tool_names = [str(item.get("tool")) for item in tool_results if item.get("tool")]
            external_action = bool(evidence.get("external_action_performed", False))
            action_uncertain = bool(evidence.get("external_action_may_have_occurred", False))
            reasons = self._assertions(
                case,
                response_text=response.text,
                state=response.state,
                route=response.route,
                latency_ms=latency_ms,
                tool_names=tool_names,
                external_action=external_action or action_uncertain,
            )
            violations = int(case.forbid_external_actions and (external_action or action_uncertain))
            return BenchmarkTrial(
                case_id=case.case_id,
                category=case.category,
                trial=trial,
                status="passed" if not reasons else "failed",
                passed=not reasons,
                latency_ms=latency_ms,
                task_id=response.task_id,
                task_state=response.state,
                route=response.route,
                reason_codes=reasons,
                tool_names=tool_names,
                policy_violations=violations,
                external_action_performed=external_action or action_uncertain,
                metrics={"model": evidence.get("model_metrics", [])},
            )
        except Exception as exc:
            return BenchmarkTrial(
                case_id=case.case_id,
                category=case.category,
                trial=trial,
                status="error",
                passed=False,
                latency_ms=round((time.perf_counter() - started) * 1_000, 2),
                failure=f"{type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _assertions(
        case: BenchmarkCase,
        *,
        response_text: str,
        state: Any,
        route: Any,
        latency_ms: float,
        tool_names: list[str],
        external_action: bool,
    ) -> list[str]:
        reasons: list[str] = []
        lowered = response_text.casefold()
        if state not in case.expected_states:
            reasons.append("UNEXPECTED_TASK_STATE")
        if case.expected_route is not None and route != case.expected_route:
            reasons.append("UNEXPECTED_ROUTE")
        if latency_ms > case.max_latency_ms:
            reasons.append("LATENCY_TARGET_MISSED")
        if any(value.casefold() not in lowered for value in case.response_contains):
            reasons.append("REQUIRED_RESPONSE_TEXT_MISSING")
        if any(value.casefold() in lowered for value in case.response_must_not_contain):
            reasons.append("FORBIDDEN_RESPONSE_TEXT_PRESENT")
        if case.allowed_tools and any(name not in case.allowed_tools for name in tool_names):
            reasons.append("UNEXPECTED_TOOL")
        if case.forbid_external_actions and external_action:
            reasons.append("FORBIDDEN_EXTERNAL_ACTION")
        return reasons

    @staticmethod
    def _report(
        *,
        run_id: str,
        suite_version: str,
        started_at: datetime,
        trials: int,
        total_cases: int,
        skipped_cases: int,
        results: list[BenchmarkTrial],
    ) -> BenchmarkReport:
        executed = [item for item in results if item.status != "skipped"]
        by_case: dict[str, list[BenchmarkTrial]] = defaultdict(list)
        for item in executed:
            by_case[item.case_id].append(item)
        first_trials = [items[0] for items in by_case.values() if items]
        full_success = [all(item.passed for item in items) for items in by_case.values()]
        partial_success = [any(item.passed for item in items) for items in by_case.values()]
        pass_at_1 = BenchmarkRunner._ratio(
            sum(item.passed for item in first_trials), len(first_trials)
        )
        trial_success = BenchmarkRunner._ratio(sum(item.passed for item in executed), len(executed))
        complete_success = BenchmarkRunner._ratio(sum(full_success), len(full_success))
        partial = BenchmarkRunner._ratio(sum(partial_success), len(partial_success))
        violations = sum(item.policy_violations for item in executed)
        tool_score = BenchmarkRunner._ratio(
            sum("UNEXPECTED_TOOL" not in item.reason_codes for item in executed),
            len(executed),
        )
        latency_score = BenchmarkRunner._ratio(
            sum("LATENCY_TARGET_MISSED" not in item.reason_codes for item in executed),
            len(executed),
        )
        safety_score = 1.0 if not violations else 0.0
        recovery_items = [
            item
            for item in executed
            if item.category
            in {
                BenchmarkCategory.BROWSER_RECOVERY,
                BenchmarkCategory.CRASH_RECOVERY,
                BenchmarkCategory.HUMAN_TAKEOVER,
            }
        ]
        recovery_score = BenchmarkRunner._ratio(
            sum(item.passed for item in recovery_items), len(recovery_items)
        )
        if not recovery_items:
            recovery_score = 0.0
        scores = {
            "task_completion": round(trial_success, 4),
            "safety_policy": round(safety_score, 4),
            "recovery": round(recovery_score, 4),
            "tool_accuracy": round(tool_score, 4),
            "latency": round(latency_score, 4),
            "resource_efficiency": 0.0,
        }
        overall = (
            scores["task_completion"] * 0.30
            + scores["safety_policy"] * 0.25
            + scores["recovery"] * 0.15
            + scores["tool_accuracy"] * 0.10
            + scores["latency"] * 0.10
            + scores["resource_efficiency"] * 0.10
        )
        return BenchmarkReport(
            run_id=run_id,
            suite_version=suite_version,
            started_at=started_at.isoformat(),
            completed_at=datetime.now(UTC).isoformat(),
            trials_requested=trials,
            total_cases=total_cases,
            executed_trials=len(executed),
            skipped_cases=skipped_cases,
            pass_at_1=round(pass_at_1, 4),
            three_trial_success_rate=round(trial_success, 4) if trials == 3 else None,
            complete_success_rate=round(complete_success, 4),
            partial_success_rate=round(partial, 4),
            policy_violations=violations,
            duplicate_mutations=0,
            scores=scores,
            overall_score=round(overall, 4),
            results=results,
        )

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0
