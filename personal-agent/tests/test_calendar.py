from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from personal_agent.calendar.models import (
    CalendarEventCreate,
    CalendarEventUpdate,
    RecurrenceFrequency,
    RecurrenceRule,
)
from personal_agent.calendar.store import CalendarConflict, CalendarStore
from personal_agent.storage import Storage
from personal_agent.types import Channel


def _calendar(tmp_path: Path) -> tuple[CalendarStore, Storage]:
    storage = Storage(tmp_path / "calendar.sqlite3")
    storage.initialize()
    calendar = CalendarStore(storage)
    calendar.initialize()
    return calendar, storage


def test_calendar_search_free_busy_conflict_update_and_cancel(tmp_path: Path) -> None:
    calendar, _ = _calendar(tmp_path)
    start = datetime.fromisoformat("2026-08-20T10:00:00+09:00")
    created = calendar.create(
        CalendarEventCreate(
            title="新幹線の打ち合わせ",
            start_at=start,
            end_at=start + timedelta(hours=1),
            location="東京駅",
            recurrence=RecurrenceRule(frequency=RecurrenceFrequency.WEEKLY, count=4),
        )
    )

    hits = calendar.search(
        query="新幹線",
        start_at=start - timedelta(days=1),
        end_at=start + timedelta(days=1),
    )
    busy = calendar.free_busy(
        start_at=start - timedelta(hours=1), end_at=start + timedelta(hours=2)
    )
    assert hits[0].event_id == created.event_id
    assert busy["busy"][0]["event_id"] == created.event_id
    assert created.timezone == "Asia/Tokyo"
    assert created.recurrence["count"] == 4

    with pytest.raises(CalendarConflict):
        calendar.create(
            CalendarEventCreate(
                title="衝突する予定",
                start_at=start + timedelta(minutes=30),
                end_at=start + timedelta(hours=2),
            )
        )

    updated = calendar.update(created.event_id, CalendarEventUpdate(location="品川駅"))
    assert updated.location == "品川駅"
    cancelled = calendar.cancel(created.event_id)
    assert cancelled.status == "cancelled"
    assert calendar.free_busy(
        start_at=start - timedelta(hours=1), end_at=start + timedelta(hours=2)
    ) == {"busy": []}


def test_calendar_rejects_naive_timestamps_and_duplicates(tmp_path: Path) -> None:
    calendar, _ = _calendar(tmp_path)
    with pytest.raises(ValueError, match="timezone"):
        CalendarEventCreate(
            title="naive",
            start_at=datetime(2026, 8, 20, 10),
            end_at=datetime(2026, 8, 20, 11),
        )

    event = CalendarEventCreate(
        title="duplicate",
        start_at=datetime.fromisoformat("2026-08-20T10:00:00+09:00"),
        end_at=datetime.fromisoformat("2026-08-20T11:00:00+09:00"),
    )
    calendar.create(event)
    with pytest.raises((ValueError, CalendarConflict)):
        calendar.create(event)


def test_recurring_follow_up_jobs_survive_and_materialize_next_occurrence(
    tmp_path: Path,
) -> None:
    _, storage = _calendar(tmp_path)
    task = storage.create_task(
        user_id="primary",
        goal="refund follow-up",
        source=Channel.WEB,
        conversation_id="calendar-test",
    )
    run_at = datetime.now(UTC) - timedelta(seconds=1)
    storage.create_scheduled_job(
        task_id=task.task_id,
        kind="follow_up",
        run_at=run_at.isoformat(),
        payload={
            "label": "返金状況を確認",
            "recurrence": {"frequency": "daily", "interval": 1, "count": 3, "until": None},
        },
    )

    assert storage.materialize_due_notifications() == 1
    jobs = storage.list_scheduled_jobs()
    assert [item["status"] for item in jobs] == ["triggered", "scheduled"]
    assert jobs[1]["payload"]["recurrence"]["count"] == 2
    notification = storage.claim_notification(source="web", conversation_id="calendar-test")
    assert notification["text"] == "返金状況を確認の時間です。"
