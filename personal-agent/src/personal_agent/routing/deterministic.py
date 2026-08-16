from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from zoneinfo import ZoneInfo

from ..types import RiskLevel, Route


class Intent(StrEnum):
    TIME = "time"
    TIMER = "timer"
    ALARM = "alarm"
    STATUS = "status"
    PAUSE = "pause"
    CANCEL = "cancel"
    MEMORY_REMEMBER = "memory_remember"
    MEMORY_FORGET = "memory_forget"
    MEMORY_SEARCH = "memory_search"
    DEEP = "deep"


@dataclass(frozen=True, slots=True)
class RouteDecision:
    route: Route
    intent: Intent
    confidence: float
    reason_code: str
    risk_level: RiskLevel
    arguments: dict[str, str] = field(default_factory=dict)


class DeterministicRouter:
    _timer = re.compile(r"(?P<value>\d{1,4})\s*(?P<unit>秒|分|時間)後(?:に)?(?P<label>.*)")
    _alarm = re.compile(
        r"(?:(?P<day>今日|明日)\s*)?(?P<hour>\d{1,2})時(?:(?P<minute>\d{1,2})分)?(?:に)?(?P<label>.*)"
    )
    _remember = re.compile(r"^(?:これを)?覚えて(?:おいて)?[：:、 ]*(?P<statement>.+)$")
    _forget = re.compile(r"^(?P<query>.+?)(?:のこと)?を?忘れて(?:ください)?$")
    _memory_search = re.compile(
        r"^(?:メモリ|記憶)(?:を)?検索[：:、 ]*(?P<query>.+)$|"
        r"^(?P<about>.+?)(?:について)?覚えて(?:い)?る[？?]?$"
    )

    def __init__(self, timezone: str = "Asia/Tokyo") -> None:
        self.timezone = ZoneInfo(timezone)

    def classify(self, text: str, *, now: datetime | None = None) -> RouteDecision:
        normalized = text.strip()
        current = now or datetime.now(self.timezone)

        if normalized in {"止めて", "キャンセル", "中止", "やめて"}:
            return RouteDecision(Route.TIER0, Intent.CANCEL, 1.0, "EXACT_CANCEL", RiskLevel.R1)
        if normalized in {"一時停止", "ポーズ", "止まって"}:
            return RouteDecision(Route.TIER0, Intent.PAUSE, 1.0, "EXACT_PAUSE", RiskLevel.R1)
        if any(phrase in normalized for phrase in ("今何してる", "状態を教えて", "ステータス")):
            return RouteDecision(Route.TIER0, Intent.STATUS, 0.99, "STATUS_PATTERN", RiskLevel.R0)
        if normalized in {"今何時", "今何時？", "時刻", "時間を教えて"}:
            return RouteDecision(
                Route.TIER0,
                Intent.TIME,
                1.0,
                "TIME_PATTERN",
                RiskLevel.R0,
                {"now": current.isoformat()},
            )

        remember = self._remember.match(normalized)
        if remember:
            return RouteDecision(
                Route.TIER0,
                Intent.MEMORY_REMEMBER,
                0.99,
                "EXPLICIT_REMEMBER",
                RiskLevel.R1,
                {"statement": remember.group("statement").strip()},
            )

        forget = self._forget.match(normalized)
        if forget:
            return RouteDecision(
                Route.TIER0,
                Intent.MEMORY_FORGET,
                0.98,
                "EXPLICIT_FORGET",
                RiskLevel.R1,
                {"query": forget.group("query").strip()},
            )

        memory_search = self._memory_search.match(normalized)
        if memory_search:
            query = memory_search.group("query") or memory_search.group("about")
            return RouteDecision(
                Route.TIER0,
                Intent.MEMORY_SEARCH,
                0.96,
                "MEMORY_SEARCH_PATTERN",
                RiskLevel.R0,
                {"query": query.strip()},
            )

        timer = self._timer.search(normalized)
        if timer and any(
            word in normalized for word in ("タイマー", "知らせ", "教えて", "起こして")
        ):
            amount = int(timer.group("value"))
            unit = timer.group("unit")
            seconds = amount if unit == "秒" else amount * 60 if unit == "分" else amount * 3600
            run_at = current + timedelta(seconds=seconds)
            label = timer.group("label").strip(" 、を") or f"{amount}{unit}タイマー"
            return RouteDecision(
                Route.TIER0,
                Intent.TIMER,
                0.99,
                "RELATIVE_TIMER_PATTERN",
                RiskLevel.R1,
                {"run_at": run_at.isoformat(), "label": label},
            )

        alarm = self._alarm.search(normalized)
        if alarm and any(word in normalized for word in ("起こして", "アラーム", "知らせて")):
            hour = int(alarm.group("hour"))
            minute = int(alarm.group("minute") or 0)
            if hour <= 23 and minute <= 59:
                run_at = current.replace(hour=hour, minute=minute, second=0, microsecond=0)
                day = alarm.group("day")
                if day == "明日":
                    run_at += timedelta(days=1)
                elif day != "今日" and run_at <= current:
                    run_at += timedelta(days=1)
                label = alarm.group("label").strip(" 、を") or "アラーム"
                return RouteDecision(
                    Route.TIER0,
                    Intent.ALARM,
                    0.98,
                    "ABSOLUTE_ALARM_PATTERN",
                    RiskLevel.R1,
                    {"run_at": run_at.isoformat(), "label": label},
                )

        return RouteDecision(
            Route.DEEP,
            Intent.DEEP,
            0.90,
            "NO_SAFE_FAST_PATH_MATCH",
            RiskLevel.R0,
        )
