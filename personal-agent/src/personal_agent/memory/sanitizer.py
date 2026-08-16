from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
SENSITIVE_KEY_PARTS = {
    "password",
    "passwd",
    "passphrase",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "session_token",
    "otp",
    "totp",
    "cvv",
    "cvc",
    "card_number",
    "account_number",
}
SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(otp|totp|verification\s*code|one[- ]time\s*(?:code|password)|"
        r"認証コード|確認コード|ワンタイム(?:パスワード|コード))\s*[:：は]?\s*[- ]?\d{4,8}\b"
    ),
    re.compile(r"(?i)\b(password|passwd|パスワード)\s*[:：=は]\s*\S+"),
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+"),
)
CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in SENSITIVE_KEY_PARTS or any(
        normalized.endswith(f"_{part}") for part in SENSITIVE_KEY_PARTS
    )


def _luhn(number: str) -> bool:
    digits = [int(char) for char in number if char.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def sanitize_text(text: str) -> tuple[str, bool]:
    result = text
    redacted = False
    for pattern in SECRET_PATTERNS:
        updated, count = pattern.subn(REDACTED, result)
        result = updated
        redacted = redacted or count > 0

    def replace_card(match: re.Match[str]) -> str:
        nonlocal redacted
        if _luhn(match.group(0)):
            redacted = True
            return REDACTED
        return match.group(0)

    result = CARD_CANDIDATE.sub(replace_card, result)
    return result, redacted


def sanitize_payload(value: Any) -> tuple[Any, bool]:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        redacted = False
        for key, item in value.items():
            if _sensitive_key(str(key)):
                result[str(key)] = REDACTED
                redacted = True
            else:
                clean, item_redacted = sanitize_payload(item)
                result[str(key)] = clean
                redacted = redacted or item_redacted
        return result, redacted
    if isinstance(value, list):
        result_list: list[Any] = []
        redacted = False
        for item in value:
            clean, item_redacted = sanitize_payload(item)
            result_list.append(clean)
            redacted = redacted or item_redacted
        return result_list, redacted
    if isinstance(value, tuple):
        return sanitize_payload(list(value))
    if isinstance(value, str):
        return sanitize_text(value)
    return value, False
