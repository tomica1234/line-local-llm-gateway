from __future__ import annotations

import pytest
from pydantic import ValidationError

from personal_agent import computer
from personal_agent.computer import ComputerService, DesktopTypeArgs


def test_normal_clipboard_metadata_and_read_return_bounded_plain_text(monkeypatch) -> None:
    value = "普通の長文です。会議の議事録を共有し、次の作業項目を整理します。" * 5
    monkeypatch.setattr(ComputerService, "_clipboard_get", staticmethod(lambda: value))

    metadata = ComputerService.clipboard_metadata()
    read = ComputerService.clipboard_read()

    assert metadata == {
        "available": True,
        "chars": len(value),
        "content_type": "text/plain",
        "secret_like": False,
    }
    assert read["text"] == value
    assert read["redacted"] is False


@pytest.mark.parametrize(
    "value",
    [
        "Authorization: Bearer AbCdEf0123456789_AbCdEf0123456789",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.AbCdEfGhIjKlMnOpQrStUvWxYz012345",  # noqa: E501  # pragma: allowlist secret
        "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",  # pragma: allowlist secret
        "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----",  # noqa: E501  # pragma: allowlist secret
        "A7v9Qp2Lm8Nx4Rz6Tk1Wy3Bc5Df0Gh9Jk2Mn7Ps4",  # pragma: allowlist secret
        "https://agent-user:credential-value@example.test/private",  # pragma: allowlist secret
    ],
)
def test_secret_like_clipboard_formats_are_redacted(monkeypatch, value: str) -> None:
    monkeypatch.setattr(ComputerService, "_clipboard_get", staticmethod(lambda: value))

    result = ComputerService.clipboard_read()

    assert result["secret_like"] is True
    assert result["redacted"] is True
    assert result["text"] == "[REDACTED_SECRET_LIKE_CLIPBOARD]"
    assert value not in str({key: item for key, item in result.items() if key != "chars"})


def test_bare_short_number_is_not_treated_as_otp_without_context() -> None:
    assert ComputerService._looks_secret_like("今日の参加人数は 123456 人ではありません") is False
    assert ComputerService._looks_secret_like("認証コード: 123456") is True


def test_desktop_type_restores_clipboard_after_success(monkeypatch) -> None:
    state = {"clipboard": "original-private-value"}
    pasted: list[str] = []
    monkeypatch.setattr(computer.os, "name", "nt")
    monkeypatch.setattr(ComputerService, "_clipboard_get", staticmethod(lambda: state["clipboard"]))
    monkeypatch.setattr(
        ComputerService,
        "_clipboard_set",
        staticmethod(lambda value: state.__setitem__("clipboard", value)),
    )
    monkeypatch.setattr(
        ComputerService,
        "_paste_from_clipboard",
        staticmethod(lambda: pasted.append(state["clipboard"])),
    )

    result = ComputerService.desktop_type("safe input", "Search field")

    assert pasted == ["safe input"]
    assert state["clipboard"] == "original-private-value"
    assert result["clipboard_restored"] is True
    assert "original-private-value" not in str(result)


def test_desktop_type_restores_clipboard_when_paste_raises(monkeypatch) -> None:
    state = {"clipboard": "original"}
    monkeypatch.setattr(computer.os, "name", "nt")
    monkeypatch.setattr(ComputerService, "_clipboard_get", staticmethod(lambda: state["clipboard"]))
    monkeypatch.setattr(
        ComputerService,
        "_clipboard_set",
        staticmethod(lambda value: state.__setitem__("clipboard", value)),
    )

    def fail_paste() -> None:
        raise RuntimeError("paste failed")

    monkeypatch.setattr(ComputerService, "_paste_from_clipboard", staticmethod(fail_paste))

    with pytest.raises(RuntimeError, match="paste failed"):
        ComputerService.desktop_type("safe input", "Search field")
    assert state["clipboard"] == "original"


def test_desktop_type_reports_restore_failure_without_exposing_original(monkeypatch) -> None:
    original = "original-secret-like-value"
    writes: list[str] = []
    monkeypatch.setattr(computer.os, "name", "nt")
    monkeypatch.setattr(ComputerService, "_clipboard_get", staticmethod(lambda: original))

    def set_clipboard(value: str) -> None:
        writes.append(value)
        if len(writes) == 2:
            raise RuntimeError("clipboard unavailable")

    monkeypatch.setattr(ComputerService, "_clipboard_set", staticmethod(set_clipboard))
    monkeypatch.setattr(ComputerService, "_paste_from_clipboard", staticmethod(lambda: None))

    result = ComputerService.desktop_type("safe input", "Search field")

    assert result["clipboard_restored"] is False
    assert result["warnings"] == ["CLIPBOARD_RESTORE_FAILED"]
    assert original not in str(result)


@pytest.mark.parametrize(
    "target",
    ["Password", "OTP", "Card number", "CVV", "API key", "Secret token", "認証コード"],
)
def test_desktop_type_rejects_secret_targets(target: str) -> None:
    with pytest.raises(ValidationError, match="Secret desktop fields"):
        DesktopTypeArgs(text="do not type", target=target)
