from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class AdapterPage:
    url: str
    title: str
    text: str


class SiteAdapter(Protocol):
    """Read-only site-specific extraction; adapters never click or grant capabilities."""

    adapter_id: str
    priority: int

    def matches(self, page: AdapterPage) -> bool: ...

    def login_state(self, page: AdapterPage) -> str: ...

    def extract_confirmation(self, page: AdapterPage) -> dict[str, Any]: ...


class SiteAdapterRegistry:
    def __init__(self, adapters: list[SiteAdapter] | None = None) -> None:
        self._adapters = list(adapters or [])

    def register(self, adapter: SiteAdapter) -> None:
        if any(item.adapter_id == adapter.adapter_id for item in self._adapters):
            raise ValueError(f"Duplicate SiteAdapter: {adapter.adapter_id}")
        self._adapters.append(adapter)

    def resolve(self, page: AdapterPage) -> SiteAdapter | None:
        matches = [adapter for adapter in self._adapters if adapter.matches(page)]
        return max(matches, key=lambda item: item.priority, default=None)

    @classmethod
    def defaults(cls) -> SiteAdapterRegistry:
        return cls([ExampleReservationAdapter()])


class ExampleReservationAdapter:
    """Example adapter used by the local E2E fixture and compatible demo sites."""

    adapter_id = "example-reservation-v1"
    priority = 10
    _hosts = {"reservation.test", "booking.test", "localhost"}

    def matches(self, page: AdapterPage) -> bool:
        host = (urlparse(page.url).hostname or "").lower()
        return host in self._hosts and bool(
            re.search(r"(?i)reservation|booking|予約|confirmation", page.title + page.text[:500])
        )

    def login_state(self, page: AdapterPage) -> str:
        if re.search(r"(?i)sign out|log out|logout|ログアウト|マイページ", page.text):
            return "authenticated"
        if re.search(r"(?i)sign in|log in|login|ログイン", page.text):
            return "authentication_required"
        return "unknown"

    def extract_confirmation(self, page: AdapterPage) -> dict[str, Any]:
        number = re.search(
            r"(?i)(?:confirmation|booking|reservation|確認|予約)"
            r"\s*(?:(?:number|id|番号|no\.?)\s*[:#：]?|[:#：])\s*"
            r"([A-Z0-9][A-Z0-9-]{4,39})",
            page.text,
        )
        total = re.search(
            r"(?i)(?:total|合計)\s*[:：]?\s*(?:JPY|¥|￥)?\s*([0-9][0-9,]*)",
            page.text,
        )
        return {
            "confirmation_number": number.group(1) if number else None,
            "total": total.group(1).replace(",", "") if total else None,
            "adapter_id": self.adapter_id,
        }
