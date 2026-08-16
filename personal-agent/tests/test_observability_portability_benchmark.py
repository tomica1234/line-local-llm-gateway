from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from personal_agent.audit import AuditLogger
from personal_agent.memory import MemoryStore
from personal_agent.memory.models import EventCreate, MemoryCreate
from personal_agent.observability import ObservabilityService
from personal_agent.portability import DataPortabilityService
from personal_agent.storage import Storage
from personal_agent.types import Channel, RiskLevel


def test_observability_reports_task_tool_and_quota_metrics(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "agent.sqlite3")
    storage.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="status",
        source=Channel.WEB,
        conversation_id="test",
    )
    action_id, _ = storage.begin_action(
        task_id=task.task_id,
        tool_name="system.status",
        idempotency_key="status-1",
        dry_run=False,
        risk_level=RiskLevel.R0,
        reason="test",
        input_data={},
    )
    storage.finish_action(action_id, status="ok", result={"status": "ok"})
    AuditLogger(storage).record(
        task_id=task.task_id,
        actor="tool_broker",
        action="system.status",
        result="ok",
        details={"duration_ms": 2.5},
    )
    service = ObservabilityService(
        storage,
        trash_root=tmp_path / "trash",
        database_quota_bytes=1,
        trash_quota_bytes=1,
    )

    health = service.health()
    metrics = service.metrics()
    assert health["database"]["integrity"] == "ok"
    assert "DATABASE_QUOTA_80_PERCENT" in health["warnings"]
    assert metrics["tasks"]["total"] == 1
    assert metrics["tools"]["by_name"] == {"system.status": 1}
    assert metrics["tools"]["duration_ms"]["average"] == 2.5
    warning_task = service.queue_quota_warning(user_id="primary")
    assert warning_task is not None
    assert service.queue_quota_warning(user_id="primary") is None
    notification = storage.claim_notification(source="web", conversation_id="pwa-primary")
    assert "DATABASE_QUOTA_80_PERCENT" in notification["text"]


def test_export_redacts_and_delete_requires_exact_confirmation(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "agent.sqlite3")
    storage.initialize()
    memory = MemoryStore(storage)
    memory.initialize()
    event = memory.append_event(
        user_id="primary",
        event=EventCreate(event_type="note", source="web", content="safe"),
    )
    memory.remember(
        user_id="primary",
        memory=MemoryCreate(statement="remember me", evidence_event_ids=[event.event_id]),
    )
    AuditLogger(storage).record(
        task_id=None,
        actor="test",
        action="secret.use",
        result="ok",
        details={"password": "never-export"},
    )
    portability = DataPortabilityService(storage, user_id="primary")

    exported = portability.export()
    assert exported["secret_values_included"] is False
    assert "never-export" not in str(exported)
    with pytest.raises(ValueError, match="DELETE:memory"):
        portability.delete("memory", confirmation="yes")
    result = portability.delete("memory", confirmation="DELETE:memory")
    assert result["deleted"]["memories"] == 1
    assert memory.list_events(user_id="primary")


def test_admin_observability_export_and_benchmark_endpoints(
    client: TestClient,
) -> None:
    headers = {"X-Admin-Token": "test-admin-token"}
    assert client.get("/api/system/health", headers=headers).status_code == 200
    assert client.get("/api/metrics", headers=headers).status_code == 200

    exported = client.get("/api/data/export", headers=headers)
    assert exported.status_code == 200
    assert exported.json()["secret_values_included"] is False
    assert "attachment" in exported.headers["content-disposition"]

    cases = client.get("/api/benchmark/cases", headers=headers).json()
    assert len(cases["cases"]) == 17
    report = client.post(
        "/api/benchmark/run",
        headers=headers,
        json={"case_ids": ["voice.time"], "trials": 1},
    )
    assert report.status_code == 200
    assert report.json()["pass_at_1"] == 1.0
    assert report.json()["results"][0]["passed"] is True
    run_id = report.json()["run_id"]
    assert client.get(f"/api/benchmark/runs/{run_id}", headers=headers).status_code == 200


def test_data_delete_endpoint_is_guarded(client: TestClient) -> None:
    headers = {"X-Admin-Token": "test-admin-token"}
    refused = client.post(
        "/api/data/delete",
        headers=headers,
        json={"scope": "activity", "confirmation": "DELETE:anything"},
    )
    assert refused.status_code == 400
    accepted = client.post(
        "/api/data/delete",
        headers=headers,
        json={"scope": "activity", "confirmation": "DELETE:activity"},
    )
    assert accepted.status_code == 200
