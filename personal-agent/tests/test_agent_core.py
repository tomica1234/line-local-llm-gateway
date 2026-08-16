from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from personal_agent.app import Runtime
from personal_agent.audit import redact
from personal_agent.browser_worker.config import BrowserWorkerSettings
from personal_agent.config import Settings
from personal_agent.core.state_machine import TaskStateMachine
from personal_agent.routing.deterministic import DeterministicRouter, Intent
from personal_agent.storage import Storage
from personal_agent.types import Channel, RiskLevel, TaskState


def test_storage_database_is_private_on_posix(tmp_path) -> None:
    storage = Storage(tmp_path / "private" / "agent.sqlite3")
    storage.initialize()
    if os.name != "nt":
        assert storage.path.stat().st_mode & 0o777 == 0o600


def test_tier0_time_skips_model(client: TestClient, fake_model) -> None:
    response = client.post(
        "/api/messages",
        json={"text": "今何時？", "source": "web", "conversation_id": "chat-1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "COMPLETED"
    assert body["route"] == "tier0"
    assert "現在は" in body["text"]
    assert fake_model.calls == []

    detail = client.get(f"/api/tasks/{body['task_id']}").json()
    states = [
        event["state"] for event in detail["events"] if event["event_type"] == "state_transition"
    ]
    assert states == ["UNDERSTANDING", "PLANNING", "EXECUTING", "VERIFYING", "COMPLETED"]


def test_timer_is_durable_and_dry_run_has_no_job(client: TestClient) -> None:
    live = client.post(
        "/api/messages",
        json={"text": "10分後に知らせて", "source": "voice", "conversation_id": "kitchen"},
    )
    dry = client.post(
        "/api/messages",
        json={
            "text": "20分後に知らせて",
            "source": "web",
            "conversation_id": "chat",
            "dry_run": True,
        },
    )

    assert live.status_code == 200
    assert dry.status_code == 200
    jobs = client.get("/api/scheduler/jobs").json()
    assert len(jobs) == 1
    assert jobs[0]["kind"] == "timer"
    assert "Dry-run" in dry.json()["text"]


def test_deep_path_uses_local_model_and_records_no_external_action(
    client: TestClient, fake_model
) -> None:
    response = client.post(
        "/api/messages",
        json={"text": "週末の過ごし方を考えて", "source": "web", "conversation_id": "chat"},
    )

    assert response.status_code == 200
    assert response.json()["route"] == "deep"
    assert response.json()["text"] == fake_model.response
    assert len(fake_model.calls) == 1
    task = client.get(f"/api/tasks/{response.json()['task_id']}").json()["task"]
    assert task["result"]["evidence"]["external_action_performed"] is False


def test_model_failure_is_resumable_from_another_channel(client: TestClient, fake_model) -> None:
    fake_model.error = ConnectionError("model offline")
    failed = client.post(
        "/api/messages",
        json={"text": "旅行の相談をしたい", "source": "web", "conversation_id": "web-chat"},
    ).json()
    assert failed["state"] == "WAITING_EXTERNAL"

    fake_model.error = None
    resumed = client.post(
        "/api/channels/voice/input",
        json={
            "text": "続きをお願い",
            "source": "web",
            "conversation_id": "living-room",
            "task_id": failed["task_id"],
        },
    )
    assert resumed.status_code == 200
    assert resumed.json()["state"] == "COMPLETED"
    assert resumed.json()["source"] == "voice"


def test_high_risk_request_is_deep_but_cannot_mutate(client: TestClient) -> None:
    response = client.post(
        "/api/messages",
        json={"text": "山田さんに3200円送金して", "source": "line", "conversation_id": "line-user"},
    )
    task = client.get(f"/api/tasks/{response.json()['task_id']}").json()["task"]
    assert task["risk_level"] == "R3"
    assert task["route"] == "deep"
    assert task["result"]["evidence"]["external_action_performed"] is False


def test_restart_pauses_transient_task(settings, fake_model) -> None:
    storage = Storage(settings.db_path)
    storage.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="long task",
        source=Channel.WEB,
        conversation_id="chat",
        risk_level=RiskLevel.R0,
    )
    machine = TaskStateMachine(storage)
    machine.transition(task.task_id, TaskState.UNDERSTANDING)
    machine.transition(task.task_id, TaskState.PLANNING)
    machine.transition(task.task_id, TaskState.EXECUTING)

    runtime = Runtime(settings, fake_model)
    recovered = runtime.storage.get_task(task.task_id)
    assert runtime.recovered_tasks == 1
    assert recovered.state is TaskState.PAUSED


def test_global_pause_requires_admin_and_blocks_execution(client: TestClient) -> None:
    unauthorized = client.put("/api/system/locks/global_pause", json={"enabled": True})
    assert unauthorized.status_code == 401

    enabled = client.put(
        "/api/system/locks/global_pause",
        json={"enabled": True},
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert enabled.status_code == 200
    assert enabled.json()["policy_version"] == 2
    blocked = client.post(
        "/api/messages",
        json={"text": "何か考えて", "source": "web", "conversation_id": "chat"},
    )
    assert blocked.json()["state"] == "PAUSED"
    assert blocked.json()["reason_code"] == "GLOBAL_PAUSE_ENABLED"


def test_redaction_recurses_and_masks_bearer_tokens() -> None:
    redacted = redact(
        {
            "password": "do-not-log",
            "nested": {"otp": "123456", "message": "Authorization: Bearer abc.def"},
        }
    )
    assert redacted["password"] == "[REDACTED]"
    assert redacted["nested"]["otp"] == "[REDACTED]"
    assert "abc.def" not in redacted["nested"]["message"]


def test_router_alarm_rolls_to_next_day() -> None:
    router = DeterministicRouter("Asia/Tokyo")
    now = datetime.fromisoformat("2026-08-13T21:00:00+09:00")
    decision = router.classify("8時に起こして", now=now)
    assert decision.intent is Intent.ALARM
    assert decision.arguments["run_at"].startswith("2026-08-14T08:00:00")


def test_service_bind_addresses_are_restricted() -> None:
    Settings(host="127.0.0.1").validate_bind_host()
    Settings(host="100.100.10.20").validate_bind_host()
    with pytest.raises(ValueError, match="localhost"):
        Settings(host="0.0.0.0").validate_bind_host()
    BrowserWorkerSettings(host="::1").validate_bind_host()
    with pytest.raises(ValueError, match="loopback"):
        BrowserWorkerSettings(host="100.100.10.20").validate_bind_host()
    wsl_worker = BrowserWorkerSettings(
        host="0.0.0.0",
        token="b" * 32,
        allowed_client_cidrs=("127.0.0.0/8", "172.16.0.0/12"),
    )
    wsl_worker.validate_runtime_security()
    assert wsl_worker.client_allowed("172.20.114.215") is True
    assert wsl_worker.client_allowed("192.168.1.204") is False
    with pytest.raises(ValueError, match="private"):
        BrowserWorkerSettings(
            host="0.0.0.0",
            token="b" * 32,
            allowed_client_cidrs=("0.0.0.0/0",),
        ).validate_runtime_security()
    Settings(admin_token="a" * 32).validate_runtime_security()
    with pytest.raises(ValueError, match="ADMIN_TOKEN"):
        Settings(admin_token="short").validate_runtime_security()
    BrowserWorkerSettings(token="b" * 32).validate_runtime_security()


def test_due_scheduler_job_is_delivered_once(client: TestClient) -> None:
    runtime = client.app.state.runtime
    task = runtime.storage.create_task(
        user_id="primary",
        goal="notify",
        source=Channel.WEB,
        conversation_id="pwa-primary",
    )
    runtime.storage.create_scheduled_job(
        task_id=task.task_id,
        kind="reminder",
        run_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        payload={"label": "テスト"},
    )

    claimed = client.post(
        "/api/notifications/claim",
        json={"source": "web", "conversation_id": "pwa-primary"},
    )
    assert claimed.status_code == 200
    assert claimed.json()["text"] == "テストの時間です。"
    notification_id = claimed.json()["notification_id"]
    assert client.post(f"/api/notifications/{notification_id}/ack").status_code == 200
    assert (
        client.post(
            "/api/notifications/claim",
            json={"source": "web", "conversation_id": "pwa-primary"},
        ).json()
        is None
    )


def test_explicit_remember_search_and_forget_are_tier0(client: TestClient, fake_model) -> None:
    remembered = client.post(
        "/api/messages",
        json={
            "text": "覚えて: 新幹線は窓側を好む",
            "source": "web",
            "conversation_id": "memory-chat",
        },
    )
    assert remembered.status_code == 200
    assert remembered.json()["route"] == "tier0"
    assert len(client.get("/api/memories").json()) == 1

    searched = client.post(
        "/api/messages",
        json={
            "text": "メモリ検索: 窓側",
            "source": "voice",
            "conversation_id": "living-room",
        },
    )
    assert "新幹線は窓側を好む" in searched.json()["text"]

    forgotten = client.post(
        "/api/messages",
        json={
            "text": "窓側を忘れて",
            "source": "web",
            "conversation_id": "memory-chat",
        },
    )
    assert "1件削除" in forgotten.json()["text"]
    assert client.get("/api/memories").json() == []
    assert fake_model.calls == []


def test_channel_messages_are_normalized_to_events_and_secrets_are_not_persisted(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/messages",
        json={
            "text": "認証コード: 123456 をどう扱う？",
            "source": "line",
            "conversation_id": "line-primary",
        },
    )
    assert response.status_code == 200
    task_id = response.json()["task_id"]
    detail = client.get(f"/api/tasks/{task_id}").json()
    assert "123456" not in detail["task"]["goal"]
    assert all("123456" not in message["text"] for message in detail["messages"])

    events = client.get("/api/events").json()
    task_events = [event for event in events if event["payload"].get("task_id") == task_id]
    assert {event["event_type"] for event in task_events} == {
        "communication.message.received",
        "communication.message.sent",
    }
    assert all("123456" not in event["content"] for event in task_events)


def test_deep_path_injects_only_relevant_approved_memory(client: TestClient, fake_model) -> None:
    created = client.post(
        "/api/memories",
        json={
            "statement": "東京旅行では静かなホテルを好む",
            "kind": "preference",
            "confidence": 0.9,
        },
    ).json()
    client.post(
        "/api/memories",
        json={
            "statement": "コーヒーは浅煎りを好む",
            "kind": "preference",
            "confidence": 0.8,
        },
    )

    response = client.post(
        "/api/messages",
        json={
            "text": "東京旅行の宿を考えて",
            "source": "web",
            "conversation_id": "travel-chat",
        },
    )
    assert response.status_code == 200
    call = fake_model.calls[-1]
    context_messages = [message for message in call if message["role"] == "system"]
    assert len(context_messages) == 1
    assert "静かなホテル" in context_messages[0]["content"]
    assert "浅煎り" not in context_messages[0]["content"]
    task = client.get(f"/api/tasks/{response.json()['task_id']}").json()["task"]
    assert task["result"]["evidence"]["memory_ids"] == [created["memory_id"]]


def test_memory_api_updates_and_deletes(client: TestClient) -> None:
    memory = client.post(
        "/api/memories",
        json={"statement": "古い好み", "confidence": 0.5},
    ).json()
    updated = client.patch(
        f"/api/memories/{memory['memory_id']}",
        json={"statement": "新しい好み", "confidence": 0.9},
    )
    assert updated.status_code == 200
    assert updated.json()["statement"] == "新しい好み"
    assert (
        client.get("/api/search", params={"q": "新しい"}).json()[0]["record_id"]
        == memory["memory_id"]
    )
    assert client.delete(f"/api/memories/{memory['memory_id']}").status_code == 200
    assert client.get("/api/memories").json() == []
