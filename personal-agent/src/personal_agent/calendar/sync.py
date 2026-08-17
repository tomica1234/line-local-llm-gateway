from __future__ import annotations

from typing import Any

from .providers import CalendarProvider
from .store import CalendarStore


class CalendarSyncService:
    """Conflict-safe provider sync; local pending mutations are never overwritten."""

    def __init__(self, store: CalendarStore) -> None:
        self.store = store
        self.providers: dict[str, CalendarProvider] = {}

    def register(self, provider: CalendarProvider) -> None:
        self.providers[provider.name] = provider

    def status(self) -> list[dict[str, Any]]:
        return [self.store.provider_state(name) for name in sorted(self.providers)]

    async def sync(self, provider_name: str, *, task_id: str) -> dict[str, Any]:
        provider = self.providers.get(provider_name)
        if provider is None:
            raise KeyError(provider_name)
        state = self.store.provider_state(provider_name)
        try:
            result = await provider.sync(task_id=task_id, sync_token=state.get("sync_token"))
            counts = {"created": 0, "updated": 0, "unchanged": 0, "conflict": 0}
            for event in result.get("events", []):
                outcome = self.store.upsert_provider_event(event)
                counts[outcome["state"]] += 1
            self.store.record_provider_state(
                provider_name,
                status="ok",
                sync_token=result.get("next_sync_token"),
            )
            return {
                "provider": provider_name,
                **counts,
                "conflicts_overwritten": False,
                "next_sync_token_stored": bool(result.get("next_sync_token")),
            }
        except Exception as exc:
            self.store.record_provider_state(
                provider_name, status="error", error=type(exc).__name__
            )
            raise
