from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from personal_agent.app import create_app
from personal_agent.config import Settings


class LocalModel:
    async def complete(self, _messages: Sequence[dict[str, object]]) -> str:
        return "local e2e response"


@pytest.mark.e2e
def test_productivity_api_todo_notification_diary_memory_calendar(tmp_path: Path) -> None:
    settings = Settings(
        db_path=tmp_path / "agent.sqlite3",
        admin_token="local-e2e-admin",
        model_base_url="http://127.0.0.1:8000/v1",
    )
    app = create_app(settings, LocalModel())
    admin = {"X-Admin-Token": settings.admin_token}
    with TestClient(app) as client:
        todo = client.post(
            "/api/todos",
            json={
                "type": "must",
                "title": "E2E report",
                "due_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "remind_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
            },
        ).json()
        notification = client.post(
            "/api/notifications/claim",
            json={"source": "web", "conversation_id": "personal-todo"},
        ).json()
        job = next(
            item
            for item in client.get("/api/scheduler/jobs").json()
            if item["job_id"] == notification["job_id"]
        )
        assert job["task_id"] == todo["source_task_id"]
        client.post(f"/api/notifications/{notification['notification_id']}/ack")
        completed = client.post(f"/api/todos/{todo['todo_id']}/complete").json()
        assert completed["status"] == "completed"

        diary = client.post(
            "/api/diary",
            json={"summary": "E2E diary", "mood": 4, "tags": ["e2e"]},
        ).json()
        assert (
            client.get("/api/diary", params={"q": "E2E"}).json()[0]["diary_id"] == diary["diary_id"]
        )

        memory = client.post(
            "/api/memories",
            json={"statement": "E2Eでは安全な再開を優先する", "kind": "preference"},
        ).json()
        assert (
            client.get("/api/search", params={"q": "安全な再開"}).json()[0]["record_id"]
            == memory["memory_id"]
        )

        start = datetime.now(UTC) + timedelta(days=1)
        event = client.post(
            "/api/calendar/events",
            headers=admin,
            json={
                "title": "E2E meeting",
                "start_at": start.isoformat(),
                "end_at": (start + timedelta(hours=1)).isoformat(),
                "timezone": "UTC",
            },
        ).json()
        listed = client.get(
            "/api/calendar/events",
            params={
                "start_at": (start - timedelta(hours=1)).isoformat(),
                "end_at": (start + timedelta(hours=2)).isoformat(),
            },
        ).json()
        assert listed[0]["event_id"] == event["event_id"]


@pytest.mark.e2e
def test_browser_fixture_contains_all_security_and_recovery_cases() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "browser_site" / "index.html"
    content = fixture.read_text(encoding="utf-8")
    for marker in (
        "current-password",
        'type="file"',
        "window.open",
        "Download receipt",
        "Booking number",
        "CAPTCHA simulated takeover",
        "Ignore prior rules",
    ):
        assert marker in content
