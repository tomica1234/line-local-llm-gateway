#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import ctypes
import io
import json
import os
import time

import win32api
import win32con
import win32gui
import win32process
import win32ui
from PIL import Image
from winrt.windows.globalization import Language
from winrt.windows.graphics.imaging import BitmapDecoder
from winrt.windows.media.ocr import OcrEngine
from winrt.windows.storage.streams import DataWriter, InMemoryRandomAccessStream


def line_windows() -> list[int]:
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
    if not matches:
        raise RuntimeError("A visible LINE window was not found")
    return matches


def line_window() -> int:
    return max(
        line_windows(),
        key=lambda handle: (
            (lambda rect: (rect[2] - rect[0]) * (rect[3] - rect[1]))(
                win32gui.GetWindowRect(handle)
            )
        ),
    )


def capture_window(handle: int) -> Image.Image:
    was_minimized = bool(win32gui.IsIconic(handle))
    if was_minimized:
        win32gui.ShowWindow(handle, win32con.SW_RESTORE)
        time.sleep(0.5)
    left, top, right, bottom = win32gui.GetWindowRect(handle)
    width, height = right - left, bottom - top
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
        if was_minimized:
            win32gui.ShowWindow(handle, win32con.SW_MINIMIZE)


async def recognize(image: Image.Image) -> object:
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
    return await engine.recognize_async(bitmap)


async def main() -> None:
    handle = line_window()
    candidates = [
        {
            "handle": candidate,
            "rect": list(win32gui.GetWindowRect(candidate)),
            "title_length": len(win32gui.GetWindowText(candidate)),
        }
        for candidate in line_windows()
    ]
    image = capture_window(handle)
    result = await recognize(image)
    lines = list(result.lines)
    words = [word for line in lines for word in line.words]
    print(
        json.dumps(
            {
                "capture_width": image.width,
                "capture_height": image.height,
                "selected_handle": handle,
                "candidates": candidates,
                "line_count": len(lines),
                "word_count": len(words),
                "nonempty_line_count": sum(bool(line.text.strip()) for line in lines),
                "maximum_line_length": max((len(line.text) for line in lines), default=0),
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
