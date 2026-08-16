from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..types import Channel, Route, TaskState


class BenchmarkCategory(StrEnum):
    VOICE_SIMPLE = "voice_simple_command"
    CALENDAR = "calendar"
    COMMUNICATION_SEARCH = "communication_search"
    MEMORY_SEARCH = "memory_search"
    BROWSER_READ_ONLY = "browser_read_only"
    BROWSER_FORM_FILL = "browser_form_fill"
    BROWSER_RECOVERY = "browser_recovery"
    AUTH = "auth"
    SHOPPING = "shopping"
    RESERVATION = "reservation"
    MONEY_SANDBOX = "money_sandbox"
    CROSS_APP = "cross_app"
    LONG_HORIZON = "long_horizon"
    PROMPT_INJECTION = "prompt_injection"
    HUMAN_TAKEOVER = "human_takeover"
    CRASH_RECOVERY = "crash_recovery"
    PROACTIVE_FOLLOW_UP = "proactive_follow_up"


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{2,99}$")
    category: BenchmarkCategory
    prompt: str = Field(min_length=1, max_length=20_000)
    source: Channel = Channel.WEB
    expected_route: Route | None = None
    expected_states: list[TaskState] = Field(default_factory=lambda: [TaskState.COMPLETED])
    response_contains: list[str] = Field(default_factory=list)
    response_must_not_contain: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    forbid_external_actions: bool = False
    required_capabilities: list[str] = Field(default_factory=list)
    max_latency_ms: float = Field(default=10_000, gt=0, le=600_000)


class BenchmarkRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_ids: list[str] = Field(default_factory=list, max_length=100)
    trials: int = Field(default=3, ge=1, le=3)


class BenchmarkTrial(BaseModel):
    case_id: str
    category: BenchmarkCategory
    trial: int
    status: str
    passed: bool
    latency_ms: float | None = None
    task_id: str | None = None
    task_state: TaskState | None = None
    route: Route | None = None
    reason_codes: list[str] = Field(default_factory=list)
    tool_names: list[str] = Field(default_factory=list)
    policy_violations: int = 0
    external_action_performed: bool = False
    failure: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)


class BenchmarkReport(BaseModel):
    run_id: str
    suite_version: str
    started_at: str
    completed_at: str
    trials_requested: int
    total_cases: int
    executed_trials: int
    skipped_cases: int
    pass_at_1: float
    three_trial_success_rate: float | None
    complete_success_rate: float
    partial_success_rate: float
    policy_violations: int
    duplicate_mutations: int
    scores: dict[str, float]
    overall_score: float
    results: list[BenchmarkTrial]
