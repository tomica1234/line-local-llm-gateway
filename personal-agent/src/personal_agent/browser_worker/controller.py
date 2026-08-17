from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel

from ..secret.models import SecretAction
from .adapters import AdapterPage, SiteAdapterRegistry
from .config import BrowserWorkerSettings
from .models import (
    ActionContext,
    BrowserAction,
    BrowserProfile,
    CheckParams,
    ClickPointParams,
    DownloadParams,
    OpenParams,
    PressParams,
    RefParams,
    ScreenshotParams,
    ScrollParams,
    SelectParams,
    SubmitParams,
    SwitchTabParams,
    TypeParams,
    UploadParams,
    WaitParams,
)
from .security import (
    quarantine_path,
    validate_navigation_url,
    validate_resolved_hostname,
    validate_upload_path,
)
from .store import BrowserWorkerStore


class BrowserUnavailable(RuntimeError):
    pass


class HumanTakeoverActive(RuntimeError):
    pass


class SecretInputRequired(PermissionError):
    pass


class StaleBrowserReference(RuntimeError):
    pass


@dataclass(slots=True)
class Takeover:
    reason: str
    task_id: str
    started_at: datetime
    expires_at: datetime


@dataclass(slots=True)
class ProfileSession:
    context: Any
    active_page: Any
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    takeover: Takeover | None = None
    timed_out_task_id: str | None = None
    snapshot_id: str | None = None
    snapshot_url: str | None = None


SNAPSHOT_SCRIPT = r"""
(snapshotId) => {
  document.documentElement.dataset.paSnapshotId = snapshotId;
  const candidates = Array.from(document.querySelectorAll(
    'a,button,input,textarea,select,summary,[role],[contenteditable="true"],h1,h2,h3'
  ));
  document.querySelectorAll('[data-pa-ref]').forEach(el => el.removeAttribute('data-pa-ref'));
  const roleFor = (el) => {
    if (el.getAttribute('role')) return el.getAttribute('role');
    const tag = el.tagName.toLowerCase();
    if (tag === 'a') return 'link';
    if (tag === 'button') return 'button';
    if (tag === 'select') return 'combobox';
    if (tag === 'textarea') return 'textbox';
    if (tag === 'input') {
      const type = (el.getAttribute('type') || 'text').toLowerCase();
      if (type === 'checkbox') return 'checkbox';
      if (type === 'radio') return 'radio';
      if (['button', 'submit', 'reset'].includes(type)) return 'button';
      return 'textbox';
    }
    return tag;
  };
  const isVisible = (el) => {
    const style = getComputedStyle(el);
    const box = el.getBoundingClientRect();
    return style.visibility !== 'hidden' && style.display !== 'none'
      && box.width > 0 && box.height > 0;
  };
  const compact = (value) => (value || '').replace(/\s+/g, ' ').trim().slice(0, 500);
    const sensitive = (el) => {
      const descriptor = [el.type, el.autocomplete, el.name, el.id, el.getAttribute('aria-label')]
        .filter(Boolean).join(' ').toLowerCase();
    return /(pass(word)?|pwd|one-time|otp|cc-|card|cvv|cvc|security.?code)/.test(descriptor)
      || /(^|\s)username(\s|$)/.test(descriptor);
  };
  const nodes = [];
  for (const el of candidates) {
    if (nodes.length >= 1000 || !isVisible(el)) continue;
    const ref = `ref-${nodes.length + 1}`;
    el.setAttribute('data-pa-ref', ref);
    const value = ('value' in el && el.value)
      ? (sensitive(el) ? '[REDACTED]' : compact(el.value)) : null;
    nodes.push({
      ref,
      tag: el.tagName.toLowerCase(),
      role: roleFor(el),
      name: compact(el.getAttribute('aria-label') || el.innerText || el.placeholder
        || el.title || el.alt),
      type: compact(el.getAttribute('type')) || null,
      autocomplete: compact(el.getAttribute('autocomplete')) || null,
      href: el.tagName.toLowerCase() === 'a' ? compact(el.href) : null,
      value,
      checked: 'checked' in el ? Boolean(el.checked) : null,
      disabled: 'disabled' in el ? Boolean(el.disabled) : null
    });
  }
  return {
    title: document.title,
    nodes,
    truncated: candidates.length > nodes.length,
    snapshot_id: snapshotId
  };
}
"""

SENSITIVE_ELEMENT_SCRIPT = r"""
(el) => {
  const descriptor = [el.type, el.autocomplete, el.name, el.id, el.getAttribute('aria-label')]
    .filter(Boolean).join(' ').toLowerCase();
  return /(pass(word)?|pwd|one-time|otp|cc-|card|cvv|cvc|security.?code)/.test(descriptor);
}
"""

SIGNAL_SCRIPT = r"""
() => {
  const visible = (el) => {
    const style = getComputedStyle(el);
    const box = el.getBoundingClientRect();
    return style.display !== 'none' && style.visibility !== 'hidden'
      && box.width > 0 && box.height > 0;
  };
  const text = (document.body?.innerText || '').toLowerCase().slice(0, 200000);
  const hasVisible = (selector) => Array.from(document.querySelectorAll(selector)).some(visible);
  const signals = [];
  if (hasVisible('iframe[src*="recaptcha" i],iframe[src*="hcaptcha" i],iframe[src*="turnstile" i],'
      + '[class*="captcha" i],[id*="captcha" i]')
      || /captcha|私はロボットではありません/.test(text)) {
    signals.push({type: 'human_required', reason: 'captcha'});
  }
  if (/passkey|security key|セキュリティキー|パスキー|face id|touch id/.test(text)) {
    signals.push({type: 'human_required', reason: 'passkey_or_biometric'});
  }
  if (/3d secure|本人認証サービス|銀行アプリで承認|approve in your app/.test(text)) {
    signals.push({type: 'human_required', reason: 'external_approval'});
  }
  if (hasVisible('input[type="password"]')) {
    signals.push({type: 'auth_required', reason: 'login_form'});
  } else if (hasVisible('input[autocomplete="username" i]')) {
    signals.push({type: 'auth_required', reason: 'username_form'});
  }
  return signals;
}
"""

SECRET_FIELD_SCRIPT = r"""
(el, action) => {
  const descriptor = [el.type, el.autocomplete, el.name, el.id, el.getAttribute('aria-label')]
    .filter(Boolean).join(' ').toLowerCase();
  if (action === 'username_fill') {
    return el.tagName.toLowerCase() === 'input'
      && ['text', 'email', 'tel', ''].includes((el.type || '').toLowerCase())
      && /(username|user.?id|login|account|e.?mail|ユーザー|メール|アカウント)/.test(descriptor);
  }
  if (action === 'password_fill') {
    return el.tagName.toLowerCase() === 'input'
      && (el.type === 'password' || /current-password|new-password/.test(descriptor));
  }
  if (action === 'totp_fill') {
    return ['input', 'textarea'].includes(el.tagName.toLowerCase())
      && /(one-time|otp|totp|verification.?code|認証コード|確認コード)/.test(descriptor);
  }
  return false;
}
"""


class PlaywrightController:
    def __init__(self, settings: BrowserWorkerSettings, store: BrowserWorkerStore):
        self.settings = settings
        self.store = store
        self._playwright: Any | None = None
        self._sessions: dict[BrowserProfile, ProfileSession] = {}
        self._create_lock = asyncio.Lock()
        self.adapters = SiteAdapterRegistry.defaults()

    async def start(self) -> None:
        if self._playwright is not None:
            return
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserUnavailable(
                "Playwright is not installed; install the browser-worker extra"
            ) from exc
        self.settings.profile_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.settings.quarantine_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._playwright = await async_playwright().start()

    async def close(self) -> None:
        for profile in list(self._sessions):
            await self.close_profile(profile)
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def close_profile(self, profile: BrowserProfile) -> None:
        session = self._sessions.pop(profile, None)
        if session is not None:
            await session.context.close()
        self.store.update_session(profile, url=None, state="closed")

    async def list_profiles(self) -> list[dict[str, Any]]:
        persisted = {item["profile"]: item for item in self.store.sessions()}
        result = []
        for profile in BrowserProfile:
            session = self._sessions.get(profile)
            item = persisted.get(profile.value, {})
            result.append(
                {
                    "profile": profile.value,
                    "running": session is not None,
                    "url": self._page(session).url if session is not None else item.get("url"),
                    "state": self._state(session)
                    if session is not None
                    else item.get("state", "closed"),
                    "takeover_reason": session.takeover.reason
                    if session is not None and session.takeover
                    else item.get("takeover_reason"),
                    "task_id": session.takeover.task_id
                    if session is not None and session.takeover
                    else item.get("task_id"),
                }
            )
        return result

    async def current_url(self, profile: BrowserProfile) -> str:
        session = await self._session(profile)
        async with session.lock:
            return self._page(session).url

    async def execute(
        self,
        profile: BrowserProfile,
        action: BrowserAction,
        params: BaseModel,
        context: ActionContext | None,
    ) -> dict[str, Any]:
        session = await self._session(profile)
        async with session.lock:
            self._expire_takeover(profile, session)
            if session.takeover is not None and action not in {
                BrowserAction.SNAPSHOT,
                BrowserAction.TABS,
                BrowserAction.SCREENSHOT,
                BrowserAction.GET_URL,
                BrowserAction.GET_DOWNLOADS,
                BrowserAction.WAIT,
            }:
                raise HumanTakeoverActive(f"Human takeover is active: {session.takeover.reason}")
            if session.timed_out_task_id is not None and action not in {
                BrowserAction.SNAPSHOT,
                BrowserAction.TABS,
                BrowserAction.SCREENSHOT,
                BrowserAction.GET_URL,
                BrowserAction.GET_DOWNLOADS,
                BrowserAction.WAIT,
            }:
                raise HumanTakeoverActive("Browser profile is paused after takeover timeout")
            pre_signals = await self._signals(self._page(session))
            preexisting_human_signal = next(
                (item for item in pre_signals if item["type"] == "human_required"), None
            )
            if (
                preexisting_human_signal
                and action
                not in {
                    BrowserAction.SNAPSHOT,
                    BrowserAction.TABS,
                    BrowserAction.SCREENSHOT,
                    BrowserAction.GET_URL,
                    BrowserAction.GET_DOWNLOADS,
                    BrowserAction.WAIT,
                }
                and context is not None
            ):
                self._set_takeover(
                    profile,
                    session,
                    reason=preexisting_human_signal["reason"],
                    task_id=context.task_id,
                    timeout_seconds=self.settings.takeover_timeout_seconds,
                )
                raise HumanTakeoverActive(
                    f"Human verification is required: {preexisting_human_signal['reason']}"
                )
            result = await self._dispatch(profile, session, action, params, context)
            page = self._page(session)
            signals = await self._signals(page)
            human_signal = next(
                (item for item in signals if item["type"] == "human_required"), None
            )
            if human_signal and session.takeover is None and context is not None:
                self._set_takeover(
                    profile,
                    session,
                    reason=human_signal["reason"],
                    task_id=context.task_id,
                    timeout_seconds=self.settings.takeover_timeout_seconds,
                )
            self.store.update_session(
                profile,
                url=page.url,
                state=self._state(session),
                task_id=session.takeover.task_id if session.takeover else None,
                reason=session.takeover.reason if session.takeover else None,
                started_at=session.takeover.started_at.isoformat() if session.takeover else None,
                expires_at=session.takeover.expires_at.isoformat() if session.takeover else None,
            )
            return {"result": result, "signals": signals}

    async def start_takeover(
        self,
        profile: BrowserProfile,
        *,
        reason: str,
        context: ActionContext,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        session = await self._session(profile)
        async with session.lock:
            self._expire_takeover(profile, session)
            if session.takeover is not None:
                raise HumanTakeoverActive("Human takeover is already active")
            self._set_takeover(
                profile,
                session,
                reason=reason,
                task_id=context.task_id,
                timeout_seconds=timeout_seconds,
            )
            return self._takeover_result(profile, session)

    async def fill_secret(
        self,
        profile: BrowserProfile,
        *,
        ref: str,
        value: str,
        action: SecretAction,
    ) -> dict[str, Any]:
        session = await self._session(profile)
        async with session.lock:
            self._expire_takeover(profile, session)
            if session.takeover is not None or session.timed_out_task_id is not None:
                raise HumanTakeoverActive("Secret fill is locked while human takeover is active")
            page = self._page(session)
            locator = await self._ref(session, page, ref)
            if not await locator.evaluate(SECRET_FIELD_SCRIPT, action.value):
                raise SecretInputRequired("Target field is incompatible with the secret action")
            await locator.fill(value)
            return {"origin_url": page.url, "filled": True}

    async def release_takeover(self, profile: BrowserProfile, *, outcome: str) -> dict[str, Any]:
        session = await self._session(profile)
        async with session.lock:
            self._expire_takeover(profile, session)
            takeover = session.takeover
            if takeover is None:
                if session.timed_out_task_id is None:
                    raise ValueError("No active or timed-out human takeover")
                task_id = session.timed_out_task_id
                if outcome == "completed":
                    session.timed_out_task_id = None
                self.store.update_session(
                    profile,
                    url=self._page(session).url,
                    state="agent" if outcome == "completed" else "paused",
                    task_id=None if outcome == "completed" else task_id,
                )
                self.store.record_audit(
                    profile=profile,
                    task_id=task_id,
                    actor="primary_user",
                    action="human_takeover.timeout_acknowledge",
                    result=outcome,
                    details={"input_values_recorded": False},
                )
                return {"state": "agent" if outcome == "completed" else "paused", "signals": []}
            session.takeover = None
            session.timed_out_task_id = takeover.task_id if outcome == "cancelled" else None
            page = self._page(session)
            signals = await self._signals(page)
            self.store.update_session(
                profile,
                url=page.url,
                state="agent" if outcome == "completed" else "paused",
            )
            self.store.record_audit(
                profile=profile,
                task_id=takeover.task_id,
                actor="primary_user",
                action="human_takeover.release",
                result=outcome,
                details={"url": page.url, "signals": signals},
            )
            return {
                "state": "agent" if outcome == "completed" else "paused",
                "task_id": takeover.task_id,
                "signals": signals,
            }

    async def takeover_status(self, profile: BrowserProfile) -> dict[str, Any]:
        session = await self._session(profile)
        async with session.lock:
            self._expire_takeover(profile, session)
            return self._takeover_result(profile, session)

    async def reap_timeouts(self) -> list[str]:
        timed_out: list[str] = []
        for profile, session in list(self._sessions.items()):
            async with session.lock:
                before = session.takeover.task_id if session.takeover else None
                self._expire_takeover(profile, session)
                if before and session.takeover is None:
                    timed_out.append(before)
        return timed_out

    async def _session(self, profile: BrowserProfile) -> ProfileSession:
        if profile in self._sessions:
            return self._sessions[profile]
        async with self._create_lock:
            if profile in self._sessions:
                return self._sessions[profile]
            await self.start()
            profile_dir = self.settings.profile_root / profile.value
            profile_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            download_dir = self.settings.quarantine_root / profile.value
            download_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            launch_options: dict[str, Any] = {
                "headless": self.settings.headless,
                "accept_downloads": True,
                "downloads_path": str(download_dir),
                "service_workers": "block",
                "args": ["--disable-extensions"] if profile is BrowserProfile.FINANCE else [],
            }
            if self.settings.browser_channel:
                launch_options["channel"] = self.settings.browser_channel
            try:
                browser_context = await self._playwright.chromium.launch_persistent_context(
                    str(profile_dir), **launch_options
                )
            except Exception as exc:
                raise BrowserUnavailable(f"Unable to start Chrome: {type(exc).__name__}") from exc
            browser_context.set_default_timeout(self.settings.navigation_timeout_ms)
            browser_context.set_default_navigation_timeout(self.settings.navigation_timeout_ms)
            await browser_context.route(
                "**/*", lambda route: self._route_navigation(route, profile)
            )
            if not browser_context.pages:
                await browser_context.new_page()
            session = ProfileSession(
                context=browser_context,
                active_page=browser_context.pages[-1],
            )
            self._sessions[profile] = session
            self.store.update_session(profile, url=self._page(session).url, state="agent")
            return session

    async def _route_navigation(self, route: Any, profile: BrowserProfile) -> None:
        request = route.request
        try:
            top_level = request.is_navigation_request() and request.frame.parent_frame is None
            if top_level:
                validate_navigation_url(
                    request.url,
                    profile=profile,
                    finance_allowlist=self.settings.finance_allowlist,
                    allow_private_navigation=self.settings.allow_private_navigation,
                )
            parsed = urlparse(request.url)
            if not self.settings.allow_private_navigation and parsed.scheme in {"http", "https"}:
                if not parsed.hostname:
                    raise ValueError("HTTP request URL must include a hostname")
                await asyncio.to_thread(validate_resolved_hostname, parsed.hostname)
        except ValueError:
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    async def _dispatch(
        self,
        profile: BrowserProfile,
        session: ProfileSession,
        action: BrowserAction,
        params: BaseModel,
        context: ActionContext | None,
    ) -> dict[str, Any]:
        page = self._page(session)
        if action is BrowserAction.OPEN:
            parsed = OpenParams.model_validate(params)
            url = validate_navigation_url(
                parsed.url,
                profile=profile,
                finance_allowlist=self.settings.finance_allowlist,
                allow_private_navigation=self.settings.allow_private_navigation,
            )
            if not self.settings.allow_private_navigation:
                hostname = urlparse(url).hostname
                if not hostname:
                    raise ValueError("Navigation URL must include a hostname")
                await asyncio.to_thread(validate_resolved_hostname, hostname)
            response = await page.goto(url, wait_until="domcontentloaded")
            await self._stabilize(page)
            session.snapshot_id = None
            session.snapshot_url = None
            return {
                "url": page.url,
                "http_status": response.status if response else None,
                "page_fingerprint": await self._page_fingerprint(page),
            }
        if action is BrowserAction.SNAPSHOT:
            await self._stabilize(page)
            snapshot = await page.evaluate(SNAPSHOT_SCRIPT, str(uuid4()))
            session.snapshot_id = str(snapshot["snapshot_id"])
            session.snapshot_url = page.url
            adapter = self._adapter_page(
                url=page.url,
                title=str(snapshot.get("title", "")),
                text=" ".join(str(node.get("name", "")) for node in snapshot.get("nodes", [])),
            )
            return {
                **snapshot,
                "url": page.url,
                "page_fingerprint": await self._page_fingerprint(page),
                "trust_level": "untrusted",
                "site_adapter": adapter.adapter_id if adapter else None,
                "login_state": adapter.login_state(
                    AdapterPage(
                        url=page.url,
                        title=str(snapshot.get("title", "")),
                        text=" ".join(
                            str(node.get("name", "")) for node in snapshot.get("nodes", [])
                        ),
                    )
                )
                if adapter
                else "unknown",
            }
        if action is BrowserAction.CLICK:
            parsed = RefParams.model_validate(params)
            before = await self._page_fingerprint(page)
            pages_before = list(session.context.pages)
            locator = await self._ref(session, page, parsed.ref)
            await locator.click()
            await self._activate_popup(session, pages_before)
            current = self._page(session)
            await self._stabilize(current)
            after = await self._page_fingerprint(current)
            return {
                "ref": parsed.ref,
                "url": current.url,
                "page_changed": before != after,
                "page_fingerprint": after,
                "popup_opened": len(session.context.pages) > len(pages_before),
            }
        if action is BrowserAction.TYPE:
            parsed = TypeParams.model_validate(params)
            locator = await self._ref(session, page, parsed.ref)
            if await locator.evaluate(SENSITIVE_ELEMENT_SCRIPT):
                raise SecretInputRequired(
                    "Sensitive inputs require Secret Broker direct-fill; browser.type is forbidden"
                )
            if parsed.clear:
                await locator.fill(parsed.text)
            else:
                await locator.press_sequentially(parsed.text)
            return {"ref": parsed.ref, "characters": len(parsed.text)}
        if action is BrowserAction.SELECT:
            parsed = SelectParams.model_validate(params)
            selected = await (await self._ref(session, page, parsed.ref)).select_option(
                parsed.values
            )
            return {"ref": parsed.ref, "selected": selected}
        if action is BrowserAction.CHECK:
            parsed = CheckParams.model_validate(params)
            locator = await self._ref(session, page, parsed.ref)
            if parsed.checked:
                await locator.check()
            else:
                await locator.uncheck()
            return {"ref": parsed.ref, "checked": parsed.checked}
        if action is BrowserAction.UPLOAD:
            parsed = UploadParams.model_validate(params)
            paths = [
                validate_upload_path(item, self.settings.upload_roots) for item in parsed.paths
            ]
            locator = await self._ref(session, page, parsed.ref)
            await locator.set_input_files([str(path) for path in paths])
            uploaded = await locator.evaluate(
                "el => Array.from(el.files || []).map(file => ({name: file.name, size: file.size}))"
            )
            if len(uploaded) != len(paths):
                raise RuntimeError("File upload verification failed")
            return {
                "ref": parsed.ref,
                "file_count": len(paths),
                "verified": True,
                "files": uploaded,
            }
        if action is BrowserAction.DOWNLOAD:
            if profile is BrowserProfile.FINANCE:
                raise PermissionError("Downloads are disabled for the finance profile")
            parsed = DownloadParams.model_validate(params)
            async with page.expect_download(timeout=parsed.timeout_ms) as download_info:
                await (await self._ref(session, page, parsed.ref)).click()
            download = await download_info.value
            target = quarantine_path(
                self.settings.quarantine_root, profile, download.suggested_filename
            )
            await download.save_as(str(target))
            failure = await download.failure()
            if failure:
                target.unlink(missing_ok=True)
                raise RuntimeError(f"Browser download failed: {failure}")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            return {
                "download_id": target.stem,
                "path": str(target),
                "size": target.stat().st_size,
                "sha256": digest,
                "suggested_filename": download.suggested_filename,
                "quarantined": True,
                "executed": False,
                "completed": True,
            }
        if action is BrowserAction.TABS:
            return {
                "tabs": [
                    {"index": index, "url": tab.url, "title": await tab.title()}
                    for index, tab in enumerate(session.context.pages)
                ]
            }
        if action is BrowserAction.NEW_TAB:
            session.active_page = await session.context.new_page()
            await session.active_page.bring_to_front()
            return {"index": len(session.context.pages) - 1, "url": session.active_page.url}
        if action is BrowserAction.CLOSE_TAB:
            pages_before = len(session.context.pages)
            await page.close()
            if session.context.pages:
                session.active_page = session.context.pages[-1]
            else:
                session.active_page = await session.context.new_page()
            await session.active_page.bring_to_front()
            return {
                "closed": True,
                "tabs_before": pages_before,
                "tabs_after": len(session.context.pages),
                "url": session.active_page.url,
            }
        if action is BrowserAction.SWITCH_TAB:
            parsed = SwitchTabParams.model_validate(params)
            pages = session.context.pages
            if parsed.index >= len(pages):
                raise ValueError("Tab index does not exist")
            await pages[parsed.index].bring_to_front()
            session.active_page = pages[parsed.index]
            return {"index": parsed.index, "url": session.active_page.url}
        if action is BrowserAction.BACK:
            response = await page.go_back(wait_until="domcontentloaded")
            await self._stabilize(page)
            session.snapshot_id = None
            return {"url": page.url, "http_status": response.status if response else None}
        if action is BrowserAction.FORWARD:
            response = await page.go_forward(wait_until="domcontentloaded")
            await self._stabilize(page)
            session.snapshot_id = None
            return {"url": page.url, "http_status": response.status if response else None}
        if action is BrowserAction.RELOAD:
            response = await page.reload(wait_until="domcontentloaded")
            await self._stabilize(page)
            session.snapshot_id = None
            return {"url": page.url, "http_status": response.status if response else None}
        if action is BrowserAction.HOVER:
            parsed = RefParams.model_validate(params)
            await (await self._ref(session, page, parsed.ref)).hover()
            return {"ref": parsed.ref, "url": page.url}
        if action is BrowserAction.PRESS:
            parsed = PressParams.model_validate(params)
            await (await self._ref(session, page, parsed.ref)).press(parsed.key)
            return {"ref": parsed.ref, "key": parsed.key, "url": page.url}
        if action is BrowserAction.SCROLL:
            parsed = ScrollParams.model_validate(params)
            await page.mouse.wheel(parsed.delta_x, parsed.delta_y)
            return {"delta_x": parsed.delta_x, "delta_y": parsed.delta_y, "url": page.url}
        if action is BrowserAction.SUBMIT:
            parsed = SubmitParams.model_validate(params)
            expected_url_prefix = parsed.expected_url_prefix
            if expected_url_prefix:
                expected = urlparse(expected_url_prefix)
                if expected.scheme not in {"http", "https"} or not expected.hostname:
                    raise ValueError("Expected URL prefix must be an absolute HTTP(S) URL")
            confirmation = (
                page.get_by_text(parsed.expected_text, exact=False)
                if parsed.expected_text
                else None
            )
            before_count = await confirmation.count() if confirmation is not None else 0
            before_url = page.url
            before_fingerprint = await self._page_fingerprint(page)
            pages_before = list(session.context.pages)
            await (await self._ref(session, page, parsed.ref)).click()
            await self._activate_popup(session, pages_before)
            deadline = asyncio.get_running_loop().time() + (parsed.timeout_ms / 1_000)
            verified_by: str | None = None
            after_count = before_count
            while asyncio.get_running_loop().time() < deadline:
                current_page = self._page(session)
                if expected_url_prefix and current_page.url.startswith(expected_url_prefix):
                    verified_by = "expected_url_prefix"
                    break
                if confirmation is not None:
                    after_count = await confirmation.count()
                    if after_count > before_count:
                        verified_by = "new_confirmation_text"
                        break
                await current_page.wait_for_timeout(200)
            current_page = self._page(session)
            await self._stabilize(current_page)
            after_fingerprint = await self._page_fingerprint(current_page)
            confirmation_evidence = await self._confirmation_evidence(current_page)
            return {
                "ref": parsed.ref,
                "before_url": before_url,
                "url": current_page.url,
                "verified": verified_by is not None,
                "verified_by": verified_by,
                "confirmation_count_increased": after_count > before_count,
                "page_changed": before_fingerprint != after_fingerprint,
                "page_fingerprint": after_fingerprint,
                "confirmation": confirmation_evidence,
                "popup_opened": len(session.context.pages) > len(pages_before),
            }
        if action is BrowserAction.WAIT:
            parsed = WaitParams.model_validate(params)
            if parsed.ref:
                await (await self._ref(session, page, parsed.ref)).wait_for(
                    state="visible", timeout=parsed.timeout_ms
                )
            else:
                await page.wait_for_timeout(parsed.timeout_ms)
            return {"waited_ms": parsed.timeout_ms, "ref": parsed.ref}
        if action is BrowserAction.SCREENSHOT:
            parsed = ScreenshotParams.model_validate(params)
            target_dir = self.settings.quarantine_root / "screenshots" / profile.value
            target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = target_dir / f"{uuid4()}.png"
            masks = [
                page.locator(
                    'input[type="password"],input[autocomplete*="one-time" i],'
                    'input[autocomplete^="cc-" i],input[name*="card" i],'
                    'input[name*="cvv" i],input[name*="cvc" i]'
                )
            ]
            await page.screenshot(
                path=str(target),
                full_page=parsed.full_page,
                mask=masks,
                mask_color="#000000",
            )
            return {"path": str(target), "secret_fields_masked": True}
        if action is BrowserAction.CLICK_POINT:
            parsed = ClickPointParams.model_validate(params)
            await page.mouse.click(parsed.x, parsed.y)
            self.store.record_audit(
                profile=profile,
                task_id=context.task_id if context else None,
                actor="agent",
                action="browser.click_point",
                result="ok",
                details={"x": parsed.x, "y": parsed.y, "target": parsed.target, "url": page.url},
            )
            return {"x": parsed.x, "y": parsed.y, "target": parsed.target, "url": page.url}
        if action is BrowserAction.GET_URL:
            return {"url": page.url}
        if action is BrowserAction.GET_DOWNLOADS:
            directory = self.settings.quarantine_root / profile.value
            items = []
            if directory.exists():
                items = [
                    {
                        "download_id": path.stem,
                        "path": str(path),
                        "size": path.stat().st_size,
                        "quarantined": True,
                    }
                    for path in sorted(directory.iterdir(), key=lambda item: item.stat().st_mtime)
                    if path.is_file()
                ][-100:]
            return {"downloads": items}
        raise ValueError(f"Unsupported browser action: {action.value}")

    async def _ref(self, session: ProfileSession, page: Any, ref: str) -> Any:
        if not re.fullmatch(r"ref-[1-9][0-9]*", ref):
            raise ValueError("Invalid DOM reference")
        if not session.snapshot_id:
            raise StaleBrowserReference("A fresh browser.snapshot is required")
        try:
            current_snapshot_id = await page.evaluate(
                "() => document.documentElement.dataset.paSnapshotId || null"
            )
        except Exception as exc:
            raise StaleBrowserReference("The page changed after the last snapshot") from exc
        if current_snapshot_id != session.snapshot_id or page.url != session.snapshot_url:
            raise StaleBrowserReference("The page changed after the last snapshot")
        locator = page.locator(f'[data-pa-ref="{ref}"]').first
        for attempt in range(3):
            try:
                if await locator.count() and await locator.is_visible():
                    return locator
            except Exception:
                pass
            if attempt < 2:
                await page.wait_for_timeout(150 * (attempt + 1))
        raise StaleBrowserReference(f"DOM reference {ref} is stale; take a new snapshot")

    @staticmethod
    async def _stabilize(page: Any, *, timeout_ms: int = 2_000) -> None:
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
        except Exception:
            pass
        previous: tuple[int, int] | None = None
        stable = 0
        for _ in range(8):
            try:
                current = tuple(
                    await page.evaluate(
                        "() => [document.querySelectorAll('*').length, "
                        "(document.body?.innerText || '').length]"
                    )
                )
            except Exception:
                return
            stable = stable + 1 if current == previous else 0
            if stable >= 2:
                return
            previous = current
            await page.wait_for_timeout(100)

    @staticmethod
    async def _page_fingerprint(page: Any) -> str:
        try:
            material = await page.evaluate(
                "() => [location.href, document.title, "
                "(document.body?.innerText || '').slice(0, 2000)].join('\\n')"
            )
        except Exception:
            material = f"{page.url}\n"
        return hashlib.sha256(str(material).encode()).hexdigest()

    @staticmethod
    async def _activate_popup(session: ProfileSession, pages_before: list[Any]) -> None:
        new_pages = [item for item in session.context.pages if item not in pages_before]
        if not new_pages:
            return
        popup = new_pages[-1]
        try:
            await popup.wait_for_load_state("domcontentloaded", timeout=3_000)
        except Exception:
            pass
        session.active_page = popup
        await popup.bring_to_front()
        session.snapshot_id = None
        session.snapshot_url = None

    async def _confirmation_evidence(self, page: Any) -> dict[str, Any]:
        try:
            text = str(await page.locator("body").inner_text(timeout=2_000))[:200_000]
        except Exception:
            return {"confirmation_number": None, "booking_id": None, "receipt_url": None}
        title = ""
        try:
            title = await page.title()
        except Exception:
            pass
        adapter_page = AdapterPage(url=page.url, title=title, text=text)
        adapter = self.adapters.resolve(adapter_page)
        if adapter:
            result = adapter.extract_confirmation(adapter_page)
            result["receipt_url"] = None
        else:
            result = {"receipt_url": None, "adapter_id": None}
        patterns = {
            "confirmation_number": (
                r"(?i)(?:confirmation|確認)\s*"
                r"(?:(?:number|番号|no\.?)\s*[:#：]?|[:#：])\s*"
                r"([A-Z0-9][A-Z0-9-]{4,39})"
            ),
            "booking_id": (
                r"(?i)(?:booking|reservation|予約)\s*"
                r"(?:(?:id|number|番号|no\.?)\s*[:#：]?|[:#：])\s*"
                r"([A-Z0-9][A-Z0-9-]{4,39})"
            ),
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, text)
            if not result.get(key):
                result[key] = match.group(1) if match else None
        try:
            receipt = page.locator('a[href*="receipt" i],a[href*="領収" i]').first
            result["receipt_url"] = (
                await receipt.get_attribute("href") if await receipt.count() else None
            )
        except Exception:
            result["receipt_url"] = None
        return result

    def _adapter_page(self, *, url: str, title: str, text: str) -> Any | None:
        return self.adapters.resolve(AdapterPage(url=url, title=title, text=text))

    @staticmethod
    def _page(session: ProfileSession) -> Any:
        if not session.context.pages:
            raise BrowserUnavailable("Browser context has no page")
        if session.active_page.is_closed():
            session.active_page = session.context.pages[-1]
        return session.active_page

    @staticmethod
    async def _signals(page: Any) -> list[dict[str, str]]:
        try:
            return await page.evaluate(SIGNAL_SCRIPT)
        except Exception:
            return []

    def _set_takeover(
        self,
        profile: BrowserProfile,
        session: ProfileSession,
        *,
        reason: str,
        task_id: str,
        timeout_seconds: int,
    ) -> None:
        now = datetime.now(UTC)
        session.timed_out_task_id = None
        session.takeover = Takeover(
            reason=reason,
            task_id=task_id,
            started_at=now,
            expires_at=now + timedelta(seconds=timeout_seconds),
        )
        page = self._page(session)
        self.store.update_session(
            profile,
            url=page.url,
            state="human",
            task_id=task_id,
            reason=reason,
            started_at=now.isoformat(),
            expires_at=session.takeover.expires_at.isoformat(),
        )
        self.store.record_audit(
            profile=profile,
            task_id=task_id,
            actor="agent",
            action="human_takeover.start",
            result="waiting_user",
            details={"reason": reason, "url": page.url, "input_values_recorded": False},
        )

    def _expire_takeover(self, profile: BrowserProfile, session: ProfileSession) -> None:
        takeover = session.takeover
        if takeover is None or datetime.now(UTC) < takeover.expires_at:
            return
        session.takeover = None
        session.timed_out_task_id = takeover.task_id
        self.store.update_session(
            profile,
            url=self._page(session).url,
            state="paused",
            task_id=takeover.task_id,
            reason="takeover_timeout",
        )
        self.store.record_audit(
            profile=profile,
            task_id=takeover.task_id,
            actor="browser_worker",
            action="human_takeover.timeout",
            result="paused",
            details={"reason": takeover.reason, "input_values_recorded": False},
        )

    @staticmethod
    def _state(session: ProfileSession | None) -> str:
        if session is None:
            return "closed"
        if session.takeover is not None:
            return "human"
        if session.timed_out_task_id is not None:
            return "paused"
        return "agent"

    def _takeover_result(self, profile: BrowserProfile, session: ProfileSession) -> dict[str, Any]:
        takeover = session.takeover
        return {
            "profile": profile.value,
            "state": self._state(session),
            "reason": takeover.reason if takeover else None,
            "task_id": takeover.task_id if takeover else session.timed_out_task_id,
            "started_at": takeover.started_at.isoformat() if takeover else None,
            "expires_at": takeover.expires_at.isoformat() if takeover else None,
            "url": self._page(session).url,
        }
