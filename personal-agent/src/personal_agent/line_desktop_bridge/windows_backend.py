from __future__ import annotations

import asyncio
import ctypes
import hashlib
import io
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from statistics import median
from typing import Any

from .config import LineDesktopBridgeSettings
from .models import SendRequest, SendResponse, SnapshotResponse, VisibleMessage
from .store import LineDesktopBridgeStore

TIME_LABEL = re.compile(
    r"^(?:\d{1,2}:\d{2}|昨日|今日|月曜|火曜|水曜|木曜|金曜|土曜|日曜|[月火水木金土日])$"
)


@dataclass(frozen=True, slots=True)
class OcrToken:
    text: str
    x: float
    y: float
    width: float
    height: float

    @property
    def center_x(self) -> float:
        return self.x + self.width / 2

    @property
    def center_y(self) -> float:
        return self.y + self.height / 2


@dataclass(frozen=True, slots=True)
class WindowCapture:
    image: Any
    list_rows: tuple[tuple[float, float, float, float], ...]
    list_right: float
    session_state: str
    window_handle: int
    was_minimized: bool


class LineSendFailure(RuntimeError):
    def __init__(self, reason_code: str, *, submitted: bool = False) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.submitted = submitted


def _normalized(value: str) -> str:
    return " ".join(value.split()).strip()


def _conversation_id(title: str) -> str:
    return "ld-" + hashlib.sha256(_normalized(title).casefold().encode("utf-8")).hexdigest()


def _message_id(conversation_id: str, kind: str, text: str, hint: str = "") -> str:
    material = f"{conversation_id}\0{kind}\0{_normalized(text)}\0{hint}"
    return "ldm-" + hashlib.sha256(material.encode("utf-8")).hexdigest()


class WindowsLineDesktopBackend:
    def __init__(
        self,
        settings: LineDesktopBridgeSettings,
        store: LineDesktopBridgeStore,
    ) -> None:
        if os.name != "nt":
            raise RuntimeError("LINE Desktop Bridge requires Windows")
        self.settings = settings
        self.store = store
        self._ui_lock = threading.RLock()
        self._operation_lock = asyncio.Lock()

    @staticmethod
    def _line_windows() -> list[int]:
        import win32api
        import win32con
        import win32gui
        import win32process

        matches: list[int] = []

        def visit(handle: int, _context: object) -> None:
            if not win32gui.IsWindowVisible(handle):
                return
            _, process_id = win32process.GetWindowThreadProcessId(handle)
            try:
                process = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                    False,
                    process_id,
                )
                executable = win32process.GetModuleFileNameEx(process, 0)
                process.Close()
            except Exception:
                return
            if os.path.basename(executable).casefold() == "line.exe":
                matches.append(handle)

        win32gui.EnumWindows(visit, None)
        return matches

    @classmethod
    def line_window(cls) -> int:
        import win32gui

        matches = cls._line_windows()
        if not matches:
            raise RuntimeError("A visible logged-in LINE window was not found")
        non_minimized = [handle for handle in matches if not win32gui.IsIconic(handle)]
        candidates = non_minimized or matches
        return max(
            candidates,
            key=lambda handle: (lambda rect: max(0, rect[2] - rect[0]) * max(0, rect[3] - rect[1]))(
                win32gui.GetWindowRect(handle)
            ),
        )

    @staticmethod
    def _session_state_for_wrapper(wrapper: Any) -> str:
        class_names = {
            str(item.element_info.class_name)
            for item in wrapper.descendants()
            if item.element_info.class_name
        }
        if class_names & {"LoginEmailPhoneNumberPanel", "LoginQRCodePanel"}:
            return "login_required"
        if class_names & {"MainChatPanel", "LcListView", "ChatListView"}:
            return "logged_in"
        return "unknown"

    @classmethod
    def session_state(cls) -> str:
        from pywinauto import Desktop

        handle = cls.line_window()
        wrapper = Desktop(backend="uia").window(handle=handle)
        return cls._session_state_for_wrapper(wrapper)

    @staticmethod
    def _print_window(handle: int) -> Any:
        import win32gui
        import win32ui
        from PIL import Image

        left, top, right, bottom = win32gui.GetWindowRect(handle)
        width, height = right - left, bottom - top
        if width < 400 or height < 300:
            raise RuntimeError("LINE window is too small to read")
        window_dc = win32gui.GetWindowDC(handle)
        source_dc = win32ui.CreateDCFromHandle(window_dc)
        memory_dc = source_dc.CreateCompatibleDC()
        bitmap = win32ui.CreateBitmap()
        try:
            bitmap.CreateCompatibleBitmap(source_dc, width, height)
            memory_dc.SelectObject(bitmap)
            rendered = ctypes.windll.user32.PrintWindow(handle, memory_dc.GetSafeHdc(), 2)
            if rendered != 1:
                raise RuntimeError("PrintWindow failed")
            info = bitmap.GetInfo()
            bits = bitmap.GetBitmapBits(True)
            return Image.frombuffer(
                "RGB",
                (info["bmWidth"], info["bmHeight"]),
                bits,
                "raw",
                "BGRX",
                0,
                1,
            ).copy()
        finally:
            win32gui.DeleteObject(bitmap.GetHandle())
            memory_dc.DeleteDC()
            source_dc.DeleteDC()
            win32gui.ReleaseDC(handle, window_dc)

    def _capture_window(self, *, keep_open: bool = False) -> WindowCapture:
        import win32con
        import win32gui
        from pywinauto import Desktop

        with self._ui_lock:
            handle = self.line_window()
            was_minimized = bool(win32gui.IsIconic(handle))
            if was_minimized:
                if not self.settings.restore_minimized_window:
                    raise RuntimeError("LINE is minimized and automatic restore is disabled")
                win32gui.ShowWindow(handle, win32con.SW_RESTORE)
                time.sleep(0.45)
            try:
                left, top, _, _ = win32gui.GetWindowRect(handle)
                wrapper = Desktop(backend="uia").window(handle=handle)
                session_state = self._session_state_for_wrapper(wrapper)
                rows = []
                for item in wrapper.descendants(control_type="ListItem"):
                    rectangle = item.rectangle()
                    if rectangle.width() < 200 or rectangle.height() < 40:
                        continue
                    rows.append(
                        (
                            float(rectangle.left - left),
                            float(rectangle.top - top),
                            float(rectangle.right - left),
                            float(rectangle.bottom - top),
                        )
                    )
                rows.sort(key=lambda row: row[1])
                image = self._print_window(handle)
                list_right = max((row[2] for row in rows), default=image.width * 0.45)
                return WindowCapture(
                    image=image,
                    list_rows=tuple(rows),
                    list_right=list_right,
                    session_state=session_state,
                    window_handle=handle,
                    was_minimized=was_minimized,
                )
            finally:
                if was_minimized and not keep_open:
                    win32gui.ShowWindow(handle, win32con.SW_MINIMIZE)

    @staticmethod
    async def _ocr(image: Any) -> list[OcrToken]:
        from winrt.windows.globalization import Language
        from winrt.windows.graphics.imaging import BitmapDecoder
        from winrt.windows.media.ocr import OcrEngine
        from winrt.windows.storage.streams import DataWriter, InMemoryRandomAccessStream

        encoded = io.BytesIO()
        image.save(encoded, format="PNG")
        stream = InMemoryRandomAccessStream()
        writer = DataWriter(stream)
        writer.write_bytes(encoded.getvalue())
        await writer.store_async()
        writer.detach_stream()
        stream.seek(0)
        decoder = await BitmapDecoder.create_async(stream)
        bitmap = await decoder.get_software_bitmap_async()
        engine = OcrEngine.try_create_from_language(Language("ja"))
        if engine is None:
            raise RuntimeError("Japanese Windows OCR is not installed")
        result = await engine.recognize_async(bitmap)
        tokens: list[OcrToken] = []
        for line in result.lines:
            for word in line.words:
                bounds = word.bounding_rect
                text = _normalized(word.text)
                if text:
                    tokens.append(
                        OcrToken(
                            text=text,
                            x=float(bounds.x),
                            y=float(bounds.y),
                            width=float(bounds.width),
                            height=float(bounds.height),
                        )
                    )
        return tokens

    @staticmethod
    def _lines(
        tokens: list[OcrToken], bounds: tuple[float, float, float, float]
    ) -> list[list[OcrToken]]:
        left, top, right, bottom = bounds
        selected = [
            token
            for token in tokens
            if left <= token.center_x <= right and top <= token.center_y <= bottom
        ]
        selected.sort(key=lambda token: (token.center_y, token.x))
        lines: list[list[OcrToken]] = []
        for token in selected:
            matching = next(
                (
                    line
                    for line in lines
                    if abs(median(item.center_y for item in line) - token.center_y)
                    <= max(7.0, token.height * 0.55)
                ),
                None,
            )
            if matching is None:
                lines.append([token])
            else:
                matching.append(token)
        for line in lines:
            line.sort(key=lambda token: token.x)
        return sorted(lines, key=lambda line: median(token.center_y for token in line))

    @staticmethod
    def _line_text(tokens: list[OcrToken]) -> str:
        return _normalized(" ".join(token.text for token in tokens))

    def _preview_messages(
        self,
        tokens: list[OcrToken],
        rows: tuple[tuple[float, float, float, float], ...],
        captured_at: str,
    ) -> list[VisibleMessage]:
        messages: list[VisibleMessage] = []
        for row in rows:
            lines = self._lines(tokens, row)
            if not lines:
                continue
            row_width = row[2] - row[0]
            title_tokens = [
                token
                for token in lines[0]
                if token.center_x < row[0] + row_width * 0.78
                and not TIME_LABEL.fullmatch(token.text)
            ]
            title = self._line_text(title_tokens)
            if not title:
                continue
            time_tokens = [
                token for token in lines[0] if token.center_x >= row[0] + row_width * 0.70
            ]
            time_label = self._line_text(time_tokens)
            preview = _normalized(" ".join(self._line_text(line) for line in lines[1:]))
            if not preview:
                continue
            conversation_id = _conversation_id(title)
            self.store.remember_conversation(conversation_id, title)
            messages.append(
                VisibleMessage(
                    message_id=_message_id(conversation_id, "chat_preview", preview, time_label),
                    conversation_id=conversation_id,
                    conversation_title=title,
                    timestamp=captured_at,
                    text=preview,
                    direction="unknown",
                    kind="chat_preview",
                    source_reference=f"line-desktop://{conversation_id}/preview",
                )
            )
        return messages

    def _conversation_rows(
        self,
        tokens: list[OcrToken],
        rows: tuple[tuple[float, float, float, float], ...],
    ) -> dict[str, tuple[float, float, float, float] | None]:
        result: dict[str, tuple[float, float, float, float] | None] = {}
        for row in rows:
            lines = self._lines(tokens, row)
            if not lines:
                continue
            row_width = row[2] - row[0]
            title = self._line_text(
                [
                    token
                    for token in lines[0]
                    if token.center_x < row[0] + row_width * 0.78
                    and not TIME_LABEL.fullmatch(token.text)
                ]
            )
            if title:
                conversation_id = _conversation_id(title)
                result[conversation_id] = None if conversation_id in result else row
        return result

    def _active_messages(
        self,
        tokens: list[OcrToken],
        *,
        width: int,
        height: int,
        list_right: float,
        captured_at: str,
    ) -> tuple[str | None, list[VisibleMessage]]:
        pane_left = min(max(list_right + 8, width * 0.35), width * 0.65)
        header_lines = self._lines(tokens, (pane_left, 48, width - 8, min(112, height * 0.24)))
        if not header_lines:
            return None, []
        title = self._line_text(header_lines[0])
        if not title:
            return None, []
        conversation_id = _conversation_id(title)
        self.store.remember_conversation(conversation_id, title)
        body_lines = self._lines(
            tokens,
            (pane_left, min(112, height * 0.24), width - 8, max(120, height - 88)),
        )
        messages: list[VisibleMessage] = []
        pane_center = (pane_left + width) / 2
        for index, line in enumerate(body_lines):
            text = self._line_text(line)
            if not text or TIME_LABEL.fullmatch(text):
                continue
            center = median(token.center_x for token in line)
            direction = "outgoing" if center > pane_center else "incoming"
            messages.append(
                VisibleMessage(
                    message_id=_message_id(
                        conversation_id,
                        "active_chat",
                        text,
                        f"{index}:{round(median(token.center_y for token in line))}",
                    ),
                    conversation_id=conversation_id,
                    conversation_title=title,
                    timestamp=captured_at,
                    text=text,
                    direction=direction,
                    kind="active_chat",
                    source_reference=f"line-desktop://{conversation_id}/visible/{index}",
                )
            )
        return conversation_id, messages

    async def snapshot(self) -> SnapshotResponse:
        async with self._operation_lock:
            captured_at = datetime.now(UTC).isoformat(timespec="milliseconds")
            capture = await asyncio.to_thread(self._capture_window)
            if capture.session_state == "login_required":
                return SnapshotResponse(
                    captured_at=captured_at,
                    session_state="login_required",
                    visible_chat_count=0,
                    messages=[],
                )
            tokens = await self._ocr(capture.image)
            previews = self._preview_messages(tokens, capture.list_rows, captured_at)
            active_id, active = self._active_messages(
                tokens,
                width=capture.image.width,
                height=capture.image.height,
                list_right=capture.list_right,
                captured_at=captured_at,
            )
            return SnapshotResponse(
                captured_at=captured_at,
                session_state=capture.session_state,
                visible_chat_count=len(previews),
                active_conversation_id=active_id,
                messages=[*previews, *active],
            )

    @staticmethod
    def _click_conversation(
        capture: WindowCapture,
        row: tuple[float, float, float, float],
    ) -> None:
        import win32api
        import win32con
        import win32gui

        left, top, _, _ = win32gui.GetWindowRect(capture.window_handle)
        x = int(left + ((row[0] + row[2]) / 2))
        y = int(top + ((row[1] + row[3]) / 2))
        win32gui.SetForegroundWindow(capture.window_handle)
        time.sleep(0.15)
        if win32gui.GetForegroundWindow() != capture.window_handle:
            raise LineSendFailure("LINE_FOCUS_DENIED")
        win32api.SetCursorPos((x, y))
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

    @staticmethod
    def _type_and_submit(capture: WindowCapture, text: str) -> None:
        import win32gui
        from pywinauto import Desktop

        left, top, right, bottom = win32gui.GetWindowRect(capture.window_handle)
        candidates = []
        wrapper = Desktop(backend="uia").window(handle=capture.window_handle)
        for edit in wrapper.descendants(control_type="Edit"):
            rectangle = edit.rectangle()
            relative_left = rectangle.left - left
            relative_top = rectangle.top - top
            if (
                relative_left <= capture.list_right
                or relative_top <= (bottom - top) * 0.55
                or rectangle.width() < 180
                or rectangle.height() < 28
            ):
                continue
            candidates.append(edit)
        if not candidates:
            raise LineSendFailure("MESSAGE_EDITOR_NOT_FOUND")
        if len(candidates) != 1:
            raise LineSendFailure("MESSAGE_EDITOR_AMBIGUOUS")
        editor = candidates[0]
        editor.click_input()
        try:
            editor.set_edit_text(text)
        except Exception as exc:
            raise LineSendFailure("MESSAGE_INPUT_FAILED") from exc
        try:
            observed = _normalized(str(editor.get_value()))
        except Exception:
            observed = _normalized(str(editor.window_text()))
        if observed != _normalized(text):
            raise LineSendFailure("MESSAGE_INPUT_VERIFICATION_FAILED")
        try:
            editor.type_keys("{ENTER}", set_foreground=False)
        except Exception as exc:
            raise LineSendFailure("SEND_RESULT_UNKNOWN", submitted=True) from exc

    @staticmethod
    def _restore_minimized(capture: WindowCapture | None) -> None:
        if capture is None or not capture.was_minimized:
            return
        import win32con
        import win32gui

        if win32gui.IsWindow(capture.window_handle):
            win32gui.ShowWindow(capture.window_handle, win32con.SW_MINIMIZE)

    async def send(self, request: SendRequest) -> SendResponse:
        if not self.settings.send_enabled:
            return SendResponse(status="rejected", reason_code="LINE_DESKTOP_SEND_DISABLED")
        if request.conversation_id not in self.settings.send_allowlist:
            return SendResponse(status="rejected", reason_code="RECIPIENT_NOT_ALLOWLISTED")
        if not request.approved:
            return SendResponse(status="rejected", reason_code="CORE_APPROVAL_REQUIRED")
        try:
            self.store.conversation_title(request.conversation_id)
        except KeyError:
            return SendResponse(status="rejected", reason_code="UNKNOWN_CONVERSATION")
        action = self.store.claim_send(
            request.idempotency_key,
            conversation_id=request.conversation_id,
            text=request.text,
        )
        if not action["claimed"]:
            status = str(action["status"])
            return SendResponse(
                status=status if status in {"ok", "submitted_unknown", "rejected"} else "rejected",
                external_message_id=action["external_message_id"],
                verified=status == "ok",
                resent=False,
                reason_code="IDEMPOTENT_REPLAY",
            )

        initial_capture: WindowCapture | None = None
        submitted = False
        try:
            async with self._operation_lock:
                initial_capture = await asyncio.to_thread(self._capture_window, keep_open=True)
                if initial_capture.session_state != "logged_in":
                    raise LineSendFailure("LINE_LOGIN_REQUIRED")
                initial_tokens = await self._ocr(initial_capture.image)
                conversation_rows = self._conversation_rows(
                    initial_tokens, initial_capture.list_rows
                )
                if request.conversation_id not in conversation_rows:
                    raise LineSendFailure("RECIPIENT_NOT_VISIBLE")
                row = conversation_rows[request.conversation_id]
                if row is None:
                    raise LineSendFailure("RECIPIENT_AMBIGUOUS")
                await asyncio.to_thread(self._click_conversation, initial_capture, row)
                await asyncio.sleep(0.6)

                selected = await asyncio.to_thread(self._capture_window, keep_open=True)
                selected_tokens = await self._ocr(selected.image)
                selected_id, _ = self._active_messages(
                    selected_tokens,
                    width=selected.image.width,
                    height=selected.image.height,
                    list_right=selected.list_right,
                    captured_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
                )
                if selected_id != request.conversation_id:
                    raise LineSendFailure("RECIPIENT_VERIFICATION_FAILED")

                submitted = True
                await asyncio.to_thread(self._type_and_submit, selected, request.text)
                await asyncio.sleep(1.0)
                verification = await asyncio.to_thread(self._capture_window, keep_open=True)
                verification_tokens = await self._ocr(verification.image)
                verified_id, visible_messages = self._active_messages(
                    verification_tokens,
                    width=verification.image.width,
                    height=verification.image.height,
                    list_right=verification.list_right,
                    captured_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
                )
                verified = verified_id == request.conversation_id and any(
                    item.direction == "outgoing"
                    and _normalized(item.text) == _normalized(request.text)
                    for item in visible_messages
                )
                if not verified:
                    raise LineSendFailure("POST_SEND_OCR_UNVERIFIED", submitted=True)
        except LineSendFailure as exc:
            result_status = "submitted_unknown" if submitted or exc.submitted else "rejected"
            self.store.finish_send(request.idempotency_key, status=result_status)
            return SendResponse(
                status=result_status,
                verified=False,
                resent=False,
                reason_code=exc.reason_code,
            )
        except Exception:
            result_status = "submitted_unknown" if submitted else "rejected"
            self.store.finish_send(request.idempotency_key, status=result_status)
            return SendResponse(
                status=result_status,
                verified=False,
                resent=False,
                reason_code="SEND_RESULT_UNKNOWN" if submitted else "LINE_UI_ERROR",
            )
        finally:
            await asyncio.to_thread(self._restore_minimized, initial_capture)

        external_message_id = (
            "lds-"
            + hashlib.sha256(
                f"{request.conversation_id}\0{request.idempotency_key}".encode()
            ).hexdigest()
        )
        self.store.finish_send(
            request.idempotency_key,
            status="ok",
            external_message_id=external_message_id,
        )
        return SendResponse(
            status="ok",
            external_message_id=external_message_id,
            verified=True,
            resent=False,
        )
