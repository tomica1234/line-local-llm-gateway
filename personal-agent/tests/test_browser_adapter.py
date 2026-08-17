from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from personal_agent.audit import AuditLogger
from personal_agent.browser.tools import browser_tools
from personal_agent.browser_worker.adapters import AdapterPage, SiteAdapterRegistry
from personal_agent.browser_worker.models import ActionContext, BrowserAction, BrowserProfile
from personal_agent.config import Settings
from personal_agent.policy.engine import PolicyEngine
from personal_agent.storage import Storage
from personal_agent.tool_broker.broker import ToolBroker
from personal_agent.types import Channel


class FakeBrowserClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def execute(
        self,
        *,
        profile: BrowserProfile,
        action: BrowserAction,
        params: dict[str, Any],
        context: ActionContext | None,
    ) -> dict[str, Any]:
        self.calls.append(
            {"profile": profile, "action": action, "params": params, "context": context}
        )
        return {
            "status": "ok",
            "profile": profile.value,
            "action": action.value,
            "result": {"url": "https://example.com", "trust_level": "untrusted"},
            "signals": [],
        }


def _broker(tmp_path: Path, client: FakeBrowserClient) -> tuple[ToolBroker, Storage, str]:
    storage = Storage(tmp_path / "core.sqlite3")
    storage.initialize()
    task = storage.create_task(
        user_id="primary",
        goal="open example",
        source=Channel.WEB,
        conversation_id="browser-test",
    )
    broker = ToolBroker(storage, PolicyEngine(storage), AuditLogger(storage))
    for definition in browser_tools(client):  # type: ignore[arg-type]
        broker.register(definition)
    return broker, storage, task.task_id


@pytest.mark.asyncio
async def test_core_browser_tool_passes_durable_action_context(tmp_path: Path) -> None:
    client = FakeBrowserClient()
    broker, _, task_id = _broker(tmp_path, client)

    result = await broker.execute(
        tool_name="browser.open",
        arguments={"profile": "general", "url": "https://example.com"},
        task_id=task_id,
        idempotency_key="core-browser-open-key",
        dry_run=False,
        reason="read public comparison page",
        allowed_names={"browser.open"},
        granted_permissions={"browser.read"},
    )

    assert result.status == "ok"
    assert result.evidence["result"]["trust_level"] == "untrusted"
    assert client.calls[0]["context"].task_id == task_id
    assert client.calls[0]["context"].idempotency_key == "core-browser-open-key"


@pytest.mark.asyncio
async def test_browser_type_value_is_not_persisted_in_core_action_or_audit(
    tmp_path: Path,
) -> None:
    client = FakeBrowserClient()
    broker, storage, task_id = _broker(tmp_path, client)
    marker = "private-form-value"

    result = await broker.execute(
        tool_name="browser.type",
        arguments={"profile": "general", "ref": "ref-1", "text": marker},
        task_id=task_id,
        idempotency_key="core-browser-type-key",
        dry_run=False,
        reason="fill a non-secret public search field",
        allowed_names={"browser.type"},
        granted_permissions={"browser.interact"},
    )

    assert result.status == "ok"
    with storage.read_connection() as connection:
        action = connection.execute(
            "SELECT input_json FROM actions WHERE idempotency_key = ?",
            ("core-browser-type-key",),
        ).fetchone()
    assert marker not in action["input_json"]
    assert marker not in str(storage.list_audit(limit=20))


@pytest.mark.asyncio
async def test_browser_lock_and_risk_policy_cannot_be_bypassed(tmp_path: Path) -> None:
    client = FakeBrowserClient()
    broker, storage, task_id = _broker(tmp_path, client)
    storage.set_safety_lock("browser_lock", True)

    locked = await broker.execute(
        tool_name="browser.snapshot",
        arguments={"profile": "general"},
        task_id=task_id,
        idempotency_key="browser-snapshot-locked",
        dry_run=False,
        reason="test browser lock",
        allowed_names={"browser.snapshot"},
        granted_permissions={"browser.read"},
    )
    storage.set_safety_lock("browser_lock", False)
    approval = await broker.execute(
        tool_name="browser.click",
        arguments={"profile": "general", "ref": "ref-1"},
        task_id=task_id,
        idempotency_key="browser-click-approval",
        dry_run=False,
        reason="test risk gate",
        allowed_names={"browser.click"},
        granted_permissions={"browser.interact"},
    )

    assert locked.status == "denied"
    assert locked.evidence["reason_code"] == "BROWSER_LOCK_ENABLED"
    assert approval.requires_approval is True
    assert client.calls == []


def test_remote_browser_worker_is_rejected_by_default(tmp_path: Path) -> None:
    settings = Settings(
        db_path=tmp_path / "core.sqlite3",
        browser_worker_base_url="https://browser.example/v1",
    )
    with pytest.raises(ValueError, match="Remote endpoint"):
        settings.validate_browser_worker_endpoint()


def test_site_adapter_is_read_only_and_extracts_confirmation() -> None:
    page = AdapterPage(
        url="https://booking.test/confirmation",
        title="Reservation confirmation",
        text="Booking number: ABC-12345 Total: JPY 11,000 Log out",
    )
    adapter = SiteAdapterRegistry.defaults().resolve(page)

    assert adapter is not None
    assert adapter.login_state(page) == "authenticated"
    evidence = adapter.extract_confirmation(page)
    assert evidence["confirmation_number"] == "ABC-12345"
    assert evidence["total"] == "11000"
