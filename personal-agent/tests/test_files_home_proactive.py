from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from personal_agent.files import FileService
from personal_agent.home.client import HomeAssistantClient
from personal_agent.home.tools import EntityArgs, SceneArgs, home_tools
from personal_agent.memory import MemoryStore
from personal_agent.memory.models import EventCreate
from personal_agent.proactive import ProactiveService
from personal_agent.storage import Storage
from personal_agent.tool_broker.broker import ToolContext
from personal_agent.types import RiskLevel, TaskState


def test_file_service_confines_paths_and_uses_recoverable_trash(tmp_path: Path) -> None:
    root = tmp_path / "documents"
    trash = tmp_path / "trash"
    root.mkdir()
    source = root / "旅程メモ.txt"
    source.write_text("外部ファイル本文", encoding="utf-8")
    (root / ".env").write_text("TOKEN=hidden", encoding="utf-8")
    service = FileService((root,), trash)

    assert service.search("旅程")[0]["path"] == str(source.resolve())
    assert service.search("env") == []
    assert service.read("旅程メモ.txt")["trust_level"] == "untrusted"

    copied = service.copy("旅程メモ.txt", "copy.txt")
    assert copied["name"] == "copy.txt"
    renamed = service.rename("copy.txt", "renamed.txt")
    assert renamed["name"] == "renamed.txt"
    deleted = service.delete_to_trash("renamed.txt")
    assert deleted["recoverable"] is True
    assert Path(str(deleted["trash_path"])).is_file()

    with pytest.raises(PermissionError):
        service.read(str(tmp_path / "outside.txt"))
    with pytest.raises(PermissionError):
        service.read(str(root / ".env"))


def test_file_service_rejects_symlink_escape_and_overwrite(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symlinks are unavailable in this environment")
    service = FileService((root,), tmp_path / "trash")

    with pytest.raises(PermissionError):
        service.read("link.txt")
    (root / "a.txt").write_text("a", encoding="utf-8")
    (root / "b.txt").write_text("b", encoding="utf-8")
    with pytest.raises(FileExistsError):
        service.copy("a.txt", "b.txt")


@pytest.mark.asyncio
async def test_home_assistant_is_private_and_uses_exact_entities() -> None:
    with pytest.raises(ValueError, match="Public"):
        HomeAssistantClient("https://8.8.8.8", "token")

    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "entity_id": "light.office",
                    "state": "on",
                    "attributes": {"friendly_name": "Office"},
                    "last_updated": "2026-08-13T00:00:00Z",
                },
            )
        return httpx.Response(200, json=[{"entity_id": "light.office"}])

    client = HomeAssistantClient(
        "http://192.168.1.10:8123",
        "test-token",
        transport=httpx.MockTransport(handler),
    )
    assert (await client.get_state("light.office"))["state"] == "on"
    result = await client.call_service("light", "turn_on", {"entity_id": "light.office"})
    assert result == {"accepted": True, "changed_states": 1}
    assert requests[0].headers["Authorization"] == "Bearer test-token"

    definition = next(item for item in home_tools(client) if item.name == "home.turn_on")
    context = ToolContext(
        task_id="task",
        action_id="action",
        idempotency_key="key",
        dry_run=False,
        reason="test",
        risk_level=RiskLevel.R1,
    )
    with pytest.raises(PermissionError, match="strong-auth"):
        await definition.handler(EntityArgs(entity_id="lock.front_door"), context)
    with pytest.raises(PermissionError, match="domain"):
        await definition.handler(EntityArgs(entity_id="script.unlock_everything"), context)

    scene = next(item for item in home_tools(client) if item.name == "home.run_scene")
    with pytest.raises(PermissionError, match="SAFE_SCENES"):
        await scene.handler(SceneArgs(entity_id="scene.relax"), context)

    safe_client = HomeAssistantClient(
        "http://192.168.1.10:8123",
        "test-token",
        safe_scene_ids=("scene.relax",),
        transport=httpx.MockTransport(handler),
    )
    safe_scene = next(item for item in home_tools(safe_client) if item.name == "home.run_scene")
    assert (await safe_scene.handler(SceneArgs(entity_id="scene.relax"), context)).status == "ok"


def test_proactive_is_opt_in_evidence_bound_and_deduplicated(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "agent.sqlite3")
    storage.initialize()
    memory = MemoryStore(storage)
    memory.initialize()
    proactive = ProactiveService(storage, user_id="alice", timezone="Asia/Tokyo")
    proactive.initialize()
    event = memory.append_event(
        user_id="alice",
        event=EventCreate(
            event_type="communication.message.received",
            source="email",
            content="注文の返金待ちです。返信が必要です。",
        ),
    )

    assert proactive.scan() == []
    proactive.update_settings(
        enabled=True,
        categories={"refund": True, "reply": False},
        quiet_hours={"start": "00:00", "end": "00:01"},
    )
    created = proactive.scan()
    assert len(created) == 1
    assert created[0]["category"] == "refund"
    assert created[0]["evidence_event_ids"] == [event.event_id]
    assert created[0]["notified_task_id"] is not None
    stored = proactive.list()[0]
    assert stored["notified_task_id"] is not None
    assert storage.get_task(stored["notified_task_id"]).user_id == "alice"
    assert storage.get_task(stored["notified_task_id"]).state is TaskState.WAITING_EXTERNAL
    assert proactive.scan() == []
    proactive.resolve(stored["opportunity_id"])
    assert storage.get_task(stored["notified_task_id"]).state is TaskState.COMPLETED
    assert storage.list_scheduled_jobs()[0]["status"] == "cancelled"


def test_proactive_quiet_hours_demotes_immediate_notifications(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "agent.sqlite3")
    storage.initialize()
    memory = MemoryStore(storage)
    memory.initialize()
    memory.append_event(
        user_id="primary",
        event=EventCreate(
            event_type="delivery",
            source="email",
            content="配送遅延が発生しています",
        ),
    )
    proactive = ProactiveService(storage)
    proactive.initialize()
    proactive.update_settings(
        enabled=True,
        categories={"delivery": True},
        quiet_hours={"start": "22:00", "end": "07:00"},
    )
    proactive._in_quiet_hours = lambda _value: True  # type: ignore[method-assign]

    created = proactive.scan()
    assert created[0]["attention"] == "DAILY_DIGEST"
    assert proactive.list()[0]["notified_task_id"] is None
