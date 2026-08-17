from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYS = {
    "authorization",
    "api_key",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "otp",
    "totp",
    "cookie",
    "card_number",
    "cvv",
    "account_number",
    "session_token",
}
TOKEN_PATTERN = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+")
PASSWORD_PATTERN = re.compile(r"(?i)\b(password|passwd|パスワード)(\s*[:：=は]\s*)\S+")
OTP_PATTERN = re.compile(
    r"(?i)\b(otp|totp|verification\s*code|認証コード|確認コード)(\s*[:：=は]?\s*)\d{4,8}\b"
)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = TOKEN_PATTERN.sub(r"\1[REDACTED]", value)
        value = PASSWORD_PATTERN.sub(r"\1\2[REDACTED]", value)
        return OTP_PATTERN.sub(r"\1\2[REDACTED]", value)
    return value
