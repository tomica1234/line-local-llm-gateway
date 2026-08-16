from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from fastapi.testclient import TestClient

from personal_agent.app import create_app
from personal_agent.config import Settings
from personal_agent.models.qwen import ModelToolCall, ModelTurn


class ToolCallingModel:
    def __init__(self) -> None:
        self.tool_turns: list[tuple[Sequence[dict[str, object]], Sequence[dict[str, object]]]] = []

    async def complete(self, messages: Sequence[dict[str, object]]) -> str:
        return "toolを使わない回答"

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> ModelTurn:
        self.tool_turns.append((list(messages), list(tools)))
        if len(self.tool_turns) == 1:
            return ModelTurn(
                tool_calls=[
                    ModelToolCall(
                        call_id="vision-too-early",
                        name="browser.screenshot",
                        arguments={"profile": "general", "full_page": False},
                    )
                ]
            )
        return ModelTurn(content="DOM snapshotを先に取得する必要があるため、操作していません。")


def test_browser_tools_are_task_scoped_and_vision_order_is_enforced(tmp_path: Path) -> None:
    model = ToolCallingModel()
    settings = Settings(
        db_path=tmp_path / "agent.sqlite3",
        model_base_url="http://127.0.0.1:8000/v1",
        admin_token="admin-token",
    )
    app = create_app(settings, model)

    with TestClient(app) as client:
        response = client.post(
            "/api/messages",
            json={
                "text": "ウェブページを調べて",
                "source": "web",
                "conversation_id": "tool-loop",
            },
        )
        detail = client.get(f"/api/tasks/{response.json()['task_id']}").json()

    assert response.status_code == 200
    assert response.json()["state"] == "COMPLETED"
    names = {tool["name"] for tool in model.tool_turns[0][1]}
    assert "browser.snapshot" in names
    assert "memory.remember" not in names
    tool_message = model.tool_turns[1][0][-1]
    assert tool_message["role"] == "tool"
    assert "DOM_SNAPSHOT_REQUIRED_BEFORE_VISION" in str(tool_message["content"])
    evidence = detail["task"]["result"]["evidence"]
    assert evidence["external_action_performed"] is False
    assert evidence["tool_results"][0]["status"] == "denied"


class ApprovalModel:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, messages: Sequence[dict[str, object]]) -> str:
        return "unused"

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> ModelTurn:
        self.calls += 1
        return ModelTurn(
            tool_calls=[
                ModelToolCall(
                    call_id="first-send",
                    name="communication.send",
                    arguments={"draft_id": "draft-123"},
                ),
                ModelToolCall(
                    call_id="must-not-run",
                    name="communication.send",
                    arguments={"draft_id": "draft-456"},
                ),
            ]
        )


def test_tool_loop_stops_immediately_at_approval_boundary(tmp_path: Path) -> None:
    model = ApprovalModel()
    settings = Settings(
        db_path=tmp_path / "approval-stop.sqlite3",
        model_base_url="http://127.0.0.1:8000/v1",
        admin_token="admin-token",
    )
    app = create_app(settings, model)

    with TestClient(app) as client:
        response = client.post(
            "/api/messages",
            json={
                "text": "下書き済みのメールを送信して",
                "source": "web",
                "conversation_id": "approval-stop",
            },
        )
        approvals = client.get(
            "/api/approvals?state=pending",
            headers={"X-Admin-Token": "admin-token"},
        ).json()

    assert response.json()["state"] == "WAITING_APPROVAL"
    assert model.calls == 1
    assert len(approvals) == 1
    assert approvals[0]["input_summary"] == {"draft_id": "draft-123"}


class RepeatedMutationModel:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, messages: Sequence[dict[str, object]]) -> str:
        return "unused"

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> ModelTurn:
        self.calls += 1
        if self.calls <= 2:
            return ModelTurn(
                tool_calls=[
                    ModelToolCall(
                        call_id=f"different-call-id-{self.calls}",
                        name="learning.propose_preference",
                        arguments={
                            "key": "travel.seat",
                            "value": "window",
                            "confidence": 0.8,
                            "evidence_event_ids": ["event-placeholder"],
                            "rationale": "test",
                        },
                    )
                ]
            )
        return ModelTurn(content="dry-runを確認しました。")


def test_model_mutation_idempotency_ignores_unstable_call_ids(tmp_path: Path) -> None:
    model = RepeatedMutationModel()
    settings = Settings(
        db_path=tmp_path / "stable-idempotency.sqlite3",
        model_base_url="http://127.0.0.1:8000/v1",
        admin_token="admin-token",
    )
    app = create_app(settings, model)

    with TestClient(app) as client:
        response = client.post(
            "/api/messages",
            json={
                "text": "旅行ではいつも窓側を選ぶ傾向を好み候補にして",
                "source": "web",
                "conversation_id": "stable-idempotency",
                "dry_run": True,
            },
        )
        task = client.get(f"/api/tasks/{response.json()['task_id']}").json()["task"]

    statuses = [item["status"] for item in task["result"]["evidence"]["tool_results"]]
    assert statuses == ["dry_run", "duplicate"]


class ReadOnlyToolModel:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, messages: Sequence[dict[str, object]]) -> str:
        return "unused"

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> ModelTurn:
        self.calls += 1
        if self.calls == 1:
            return ModelTurn(
                tool_calls=[
                    ModelToolCall(
                        call_id="local-search",
                        name="communication.search",
                        arguments={"query": "見積もり", "limit": 5},
                    )
                ]
            )
        return ModelTurn(content="該当メッセージはありません。")


def test_successful_read_tool_is_not_reported_as_external_action(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            db_path=tmp_path / "read-evidence.sqlite3",
            model_base_url="http://127.0.0.1:8000/v1",
            admin_token="admin-token",
        ),
        ReadOnlyToolModel(),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/messages",
            json={
                "text": "Slackの見積もりメッセージを検索して",
                "source": "web",
                "conversation_id": "read-only-evidence",
            },
        )
        task = client.get(f"/api/tasks/{response.json()['task_id']}").json()["task"]

    evidence = task["result"]["evidence"]
    assert evidence["tool_results"][0]["mutation"] is False
    assert evidence["external_action_performed"] is False
