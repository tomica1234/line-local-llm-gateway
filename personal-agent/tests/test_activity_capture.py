from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient


def activity(url: str, *, title: str = "Page", query: str | None = None) -> dict[str, object]:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "device_id": "iphone-primary",
        "browser": "safari",
        "private_mode": True,
        "url": url,
        "page_title": title,
        "search_query": query,
        "referrer_domain": "example.test",
        "estimated_dwell_time": 12.5,
        "tab_session_id": "tab-1",
    }


def test_activity_capture_is_off_by_default(client: TestClient) -> None:
    response = client.post(
        "/api/activity/batch",
        json={"events": [activity("https://example.com/")]},
        headers={"X-Activity-Token": "test-activity-token"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "accepted": 1,
        "stored": 0,
        "dropped": 1,
        "origin_only": 0,
        "disabled": True,
    }
    assert client.get("/api/events").json() == []


def test_activity_requires_dedicated_token(client: TestClient) -> None:
    response = client.post(
        "/api/activity/batch",
        json={"events": [activity("https://example.com/")]},
    )
    assert response.status_code == 401


def test_activity_privacy_domain_blocking_and_url_sanitization(
    client: TestClient,
) -> None:
    enabled = client.put(
        "/api/activity/status",
        json={"enabled": True, "blocked_domains": ["blocked.example"]},
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert enabled.status_code == 200

    response = client.post(
        "/api/activity/batch",
        json={
            "events": [
                activity(
                    "https://search.example/results?q=onsen&token=never-store#private",
                    title="温泉検索",
                    query="箱根 温泉",
                ),
                activity(
                    "https://secure.bank.example/transfer?token=secret",
                    title="振込画面",
                ),
                activity("https://blocked.example/private", title="保存禁止"),
            ]
        },
        headers={"X-Activity-Token": "test-activity-token"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "accepted": 3,
        "stored": 2,
        "dropped": 1,
        "origin_only": 1,
        "disabled": False,
    }

    events = [
        event
        for event in client.get("/api/events").json()
        if event["event_type"] == "browser.activity"
    ]
    assert len(events) == 2
    standard = next(event for event in events if event["payload"].get("domain") == "search.example")
    assert "箱根 温泉" in standard["content"]
    assert "token" not in standard["payload"]["url"]
    assert "#private" not in standard["payload"]["url"]

    sensitive = next(
        event for event in events if event["payload"].get("domain") == "secure.bank.example"
    )
    assert sensitive["content"] == ""
    assert sensitive["payload"] == {
        "origin": "https://secure.bank.example",
        "domain": "secure.bank.example",
    }
    assert sensitive["source_reference"] == "https://secure.bank.example"
    assert not any("保存禁止" in event["content"] for event in events)

    storage = client.app.state.runtime.storage
    with storage.read_connection() as connection:
        row = connection.execute(
            "SELECT content, payload_json, source_reference, provenance_json "
            "FROM raw_events WHERE event_id=?",
            (sensitive["event_id"],),
        ).fetchone()
    persisted = json.dumps(dict(row), ensure_ascii=False)
    for forbidden in (
        "/transfer",
        "token=secret",
        "振込画面",
        "example.test",
    ):
        assert forbidden not in persisted
