from __future__ import annotations

import base64
import ctypes
import os
from ctypes import wintypes
from typing import Protocol


class SecretProtector(Protocol):
    name: str

    def protect(self, plaintext: bytes) -> bytes: ...

    def unprotect(self, ciphertext: bytes) -> bytes: ...


class DpapiProtector:
    """Windows user-scoped DPAPI with UI disabled and application entropy."""

    name = "windows-dpapi-user"
    _CRYPTPROTECT_UI_FORBIDDEN = 0x1
    _entropy = b"local-personal-agent/browser-worker/v1"

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Windows DPAPI is only available on Windows")

    @classmethod
    def _blob(cls, value: bytes) -> tuple[DpapiProtector._DataBlob, object]:
        buffer = ctypes.create_string_buffer(value, len(value))
        blob = cls._DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
        return blob, buffer

    def protect(self, plaintext: bytes) -> bytes:
        return self._call(plaintext, decrypt=False)

    def unprotect(self, ciphertext: bytes) -> bytes:
        return self._call(ciphertext, decrypt=True)

    def _call(self, value: bytes, *, decrypt: bool) -> bytes:
        input_blob, input_buffer = self._blob(value)
        entropy_blob, entropy_buffer = self._blob(self._entropy)
        output_blob = self._DataBlob()
        description = wintypes.LPWSTR()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if decrypt:
            success = crypt32.CryptUnprotectData(
                ctypes.byref(input_blob),
                ctypes.byref(description),
                ctypes.byref(entropy_blob),
                None,
                None,
                self._CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
        else:
            success = crypt32.CryptProtectData(
                ctypes.byref(input_blob),
                "Local Personal Agent credential",
                ctypes.byref(entropy_blob),
                None,
                None,
                self._CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(output_blob),
            )
        _ = input_buffer, entropy_buffer
        if not success:
            raise ctypes.WinError()
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            if output_blob.pbData:
                ctypes.memset(output_blob.pbData, 0, output_blob.cbData)
                kernel32.LocalFree(output_blob.pbData)
            if description:
                kernel32.LocalFree(description)


class FernetProtector:
    """Optional non-Windows backend; its key must come from an external secret source."""

    name = "fernet-external-key"

    def __init__(self, key: str):
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise RuntimeError("Install the auth extra to use the Fernet backend") from exc
        try:
            decoded = base64.urlsafe_b64decode(key.encode("ascii"))
        except Exception as exc:
            raise ValueError("Secret master key is not valid URL-safe base64") from exc
        if len(decoded) != 32:
            raise ValueError("Secret master key must encode exactly 32 random bytes")
        self._fernet = Fernet(key.encode("ascii"))

    def protect(self, plaintext: bytes) -> bytes:
        return self._fernet.encrypt(plaintext)

    def unprotect(self, ciphertext: bytes) -> bytes:
        return self._fernet.decrypt(ciphertext)


def protector_from_environment() -> SecretProtector:
    if os.name == "nt":
        return DpapiProtector()
    key = os.getenv("PERSONAL_AGENT_SECRET_MASTER_KEY", "")
    if not key:
        raise RuntimeError(
            "Secret operations require Windows DPAPI or PERSONAL_AGENT_SECRET_MASTER_KEY"
        )
    return FernetProtector(key)
