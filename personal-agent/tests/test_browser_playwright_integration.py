from __future__ import annotations

from pathlib import Path

import pytest

from personal_agent.browser_worker.config import BrowserWorkerSettings
from personal_agent.browser_worker.controller import (
    PlaywrightController,
    SecretInputRequired,
)
from personal_agent.browser_worker.models import (
    ActionContext,
    BrowserAction,
    BrowserProfile,
    EmptyParams,
    ScreenshotParams,
    ScrollParams,
    SubmitParams,
    TypeParams,
)
from personal_agent.browser_worker.store import BrowserWorkerStore


@pytest.mark.integration
@pytest.mark.browser
@pytest.mark.asyncio
async def test_real_playwright_snapshot_type_secret_guard_and_masked_screenshot(
    tmp_path: Path,
) -> None:
    settings = BrowserWorkerSettings(
        token="integration-token",
        profile_root=tmp_path / "profiles",
        quarantine_root=tmp_path / "quarantine",
        state_db_path=tmp_path / "worker.sqlite3",
        browser_channel="",
        headless=True,
    )
    store = BrowserWorkerStore(settings.state_db_path)
    store.initialize()
    controller = PlaywrightController(settings, store)
    context = ActionContext(
        task_id="playwright-task",
        action_id="playwright-action",
        idempotency_key="playwright-integration-key",
        reason="verify real browser primitives",
    )

    try:
        session = await controller._session(BrowserProfile.GENERAL)
        page = controller._page(session)
        await page.set_content(
            """
            <main>
              <h1>Form test</h1>
              <label>Query <input name="query" aria-label="Query"></label>
              <label>Password <input type="password" name="password" value="secret"></label>
              <button type="button"
                onclick="document.querySelector('#result').textContent='Saved locally'">
                Continue
              </button>
              <p id="result"></p>
            </main>
            """
        )
        snapshot = await controller.execute(
            BrowserProfile.GENERAL,
            BrowserAction.SNAPSHOT,
            EmptyParams(),
            None,
        )
        nodes = snapshot["result"]["nodes"]
        query_ref = next(node["ref"] for node in nodes if node["name"] == "Query")
        password_node = next(node for node in nodes if node["type"] == "password")
        assert password_node["value"] == "[REDACTED]"

        await controller.execute(
            BrowserProfile.GENERAL,
            BrowserAction.TYPE,
            TypeParams(ref=query_ref, text="local browser"),
            context,
        )
        assert await page.locator('input[name="query"]').input_value() == "local browser"

        await controller.execute(
            BrowserProfile.GENERAL,
            BrowserAction.SCROLL,
            ScrollParams(delta_y=100),
            context,
        )

        continue_ref = next(node["ref"] for node in nodes if node["name"] == "Continue")
        submitted = await controller.execute(
            BrowserProfile.GENERAL,
            BrowserAction.SUBMIT,
            SubmitParams(ref=continue_ref, expected_text="Saved locally"),
            context,
        )
        assert submitted["result"]["verified"] is True
        assert submitted["result"]["verified_by"] == "new_confirmation_text"

        with pytest.raises(SecretInputRequired):
            await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.TYPE,
                TypeParams(ref=password_node["ref"], text="must-not-enter"),
                context,
            )

        screenshot = await controller.execute(
            BrowserProfile.GENERAL,
            BrowserAction.SCREENSHOT,
            ScreenshotParams(),
            None,
        )
        screenshot_path = Path(screenshot["result"]["path"])
        assert screenshot_path.is_file()
        assert screenshot["result"]["secret_fields_masked"] is True
    finally:
        await controller.close()
