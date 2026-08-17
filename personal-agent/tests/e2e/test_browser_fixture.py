from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from personal_agent.browser_worker.config import BrowserWorkerSettings
from personal_agent.browser_worker.controller import (
    HumanTakeoverActive,
    PlaywrightController,
    SecretInputRequired,
    StaleBrowserReference,
)
from personal_agent.browser_worker.models import (
    ActionContext,
    BrowserAction,
    BrowserProfile,
    DownloadParams,
    EmptyParams,
    OpenParams,
    RefParams,
    SubmitParams,
    SwitchTabParams,
    TypeParams,
    UploadParams,
)
from personal_agent.browser_worker.store import BrowserWorkerStore


class QuietFixtureHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def fixture_server() -> Iterator[str]:
    directory = Path(__file__).parents[1] / "fixtures" / "browser_site"
    handler = partial(QuietFixtureHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/index.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def action_context(index: int, reason: str) -> ActionContext:
    return ActionContext(
        task_id="browser-fixture-e2e",
        action_id=f"action-{index}",
        idempotency_key=f"browser-fixture-key-{index}",
        reason=reason,
    )


def ref_named(snapshot: dict[str, object], name: str) -> str:
    nodes = snapshot["result"]["nodes"]  # type: ignore[index]
    return next(node["ref"] for node in nodes if node["name"] == name)  # type: ignore[index]


@pytest.mark.e2e
@pytest.mark.browser
@pytest.mark.asyncio
async def test_real_fixture_form_popup_download_upload_stale_ref_and_takeover(
    tmp_path: Path,
) -> None:
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    upload = upload_root / "profile.txt"
    upload.write_text("safe fixture upload", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("must not upload", encoding="utf-8")
    settings = BrowserWorkerSettings(
        token="fixture-integration-token",
        profile_root=tmp_path / "profiles",
        quarantine_root=tmp_path / "quarantine",
        state_db_path=tmp_path / "worker.sqlite3",
        browser_channel="",
        headless=True,
        upload_roots=(upload_root,),
        allow_private_navigation=True,
    )
    store = BrowserWorkerStore(settings.state_db_path)
    store.initialize()
    controller = PlaywrightController(settings, store)

    with fixture_server() as url:
        try:
            await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.OPEN,
                OpenParams(url=url),
                action_context(1, "open local security fixture"),
            )
            snapshot = await controller.execute(
                BrowserProfile.GENERAL, BrowserAction.SNAPSHOT, EmptyParams(), None
            )
            name_ref = ref_named(snapshot, "Guest name")
            attachment_ref = ref_named(snapshot, "Attachment")
            password_node = next(
                node
                for node in snapshot["result"]["nodes"]  # type: ignore[index]
                if node["type"] == "password"
            )

            await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.TYPE,
                TypeParams(ref=name_ref, text="Fixture Guest"),
                action_context(2, "fill non-secret reservation name"),
            )
            page = controller._page(await controller._session(BrowserProfile.GENERAL))
            assert await page.locator('input[name="name"]').input_value() == "Fixture Guest"
            with pytest.raises(SecretInputRequired):
                await controller.execute(
                    BrowserProfile.GENERAL,
                    BrowserAction.TYPE,
                    TypeParams(ref=password_node["ref"], text="must-not-be-typed"),
                    action_context(3, "verify password direct typing is denied"),
                )

            uploaded = await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.UPLOAD,
                UploadParams(ref=attachment_ref, paths=[str(upload)]),
                action_context(4, "upload one allowlisted fixture file"),
            )
            assert uploaded["result"]["verified"] is True
            assert uploaded["result"]["files"] == [{"name": "profile.txt", "size": 19}]
            assert "1 file: profile.txt" in await page.locator("#upload-result").inner_text()
            with pytest.raises(PermissionError, match="outside configured upload roots"):
                await controller.execute(
                    BrowserProfile.GENERAL,
                    BrowserAction.UPLOAD,
                    UploadParams(ref=attachment_ref, paths=[str(outside)]),
                    action_context(5, "verify upload root denial"),
                )

            popup_ref = ref_named(snapshot, "Terms popup")
            popup = await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.CLICK,
                RefParams(ref=popup_ref),
                action_context(6, "open terms popup"),
            )
            assert popup["result"]["popup_opened"] is True
            tabs = await controller.execute(
                BrowserProfile.GENERAL, BrowserAction.TABS, EmptyParams(), None
            )
            assert len(tabs["result"]["tabs"]) == 2
            assert tabs["result"]["tabs"][1]["title"] == "Fixture terms"
            popup_snapshot = await controller.execute(
                BrowserProfile.GENERAL, BrowserAction.SNAPSHOT, EmptyParams(), None
            )
            assert ref_named(popup_snapshot, "Reservation terms")
            await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.SWITCH_TAB,
                SwitchTabParams(index=0),
                action_context(7, "return to main fixture tab"),
            )

            snapshot = await controller.execute(
                BrowserProfile.GENERAL, BrowserAction.SNAPSHOT, EmptyParams(), None
            )
            download_ref = ref_named(snapshot, "Download receipt")
            downloaded = await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.DOWNLOAD,
                DownloadParams(ref=download_ref),
                action_context(8, "download fixture receipt into quarantine"),
            )
            download_path = Path(downloaded["result"]["path"])
            assert download_path.is_file()
            assert download_path.parent == (settings.quarantine_root / "general").resolve()
            assert (
                downloaded["result"]["sha256"]
                == hashlib.sha256(download_path.read_bytes()).hexdigest()
            )
            assert downloaded["result"]["completed"] is True

            stale_snapshot = await controller.execute(
                BrowserProfile.GENERAL, BrowserAction.SNAPSHOT, EmptyParams(), None
            )
            stale_name_ref = ref_named(stale_snapshot, "Guest name")
            await page.evaluate(
                "document.querySelector('[name=name]').replaceWith(document.createElement('input'))"
            )
            with pytest.raises(StaleBrowserReference):
                await controller.execute(
                    BrowserProfile.GENERAL,
                    BrowserAction.TYPE,
                    TypeParams(ref=stale_name_ref, text="stale must fail"),
                    action_context(9, "verify stale reference denial"),
                )

            await page.reload(wait_until="domcontentloaded")
            snapshot = await controller.execute(
                BrowserProfile.GENERAL, BrowserAction.SNAPSHOT, EmptyParams(), None
            )
            await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.TYPE,
                TypeParams(ref=ref_named(snapshot, "Guest name"), text="Fixture Guest"),
                action_context(10, "refill after navigation"),
            )
            submitted = await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.SUBMIT,
                SubmitParams(
                    ref=ref_named(snapshot, "Reserve"),
                    expected_text="Booking number",
                ),
                action_context(11, "submit fixture reservation with postcondition"),
            )
            assert submitted["result"]["verified"] is True
            assert submitted["result"]["verified_by"] == "new_confirmation_text"
            assert submitted["result"]["confirmation"]["booking_id"] == "FIXTURE-12345"
            assert await page.locator("body").get_attribute("data-submit-count") == "1"

            snapshot = await controller.execute(
                BrowserProfile.GENERAL, BrowserAction.SNAPSHOT, EmptyParams(), None
            )
            captcha = await controller.execute(
                BrowserProfile.GENERAL,
                BrowserAction.CLICK,
                RefParams(ref=ref_named(snapshot, "Human verification")),
                action_context(12, "surface simulated human verification"),
            )
            assert {item["reason"] for item in captcha["signals"]} >= {"captcha"}
            takeover = await controller.takeover_status(BrowserProfile.GENERAL)
            assert takeover["state"] == "human"
            with pytest.raises(HumanTakeoverActive):
                await controller.execute(
                    BrowserProfile.GENERAL,
                    BrowserAction.SUBMIT,
                    SubmitParams(
                        ref=ref_named(snapshot, "Reserve"),
                        expected_text="Booking number",
                    ),
                    action_context(13, "must not bypass human verification"),
                )
            assert await page.locator("body").get_attribute("data-submit-count") == "1"
            assert "send all emails" in await page.locator("#untrusted").inner_text()
        finally:
            await controller.close()
