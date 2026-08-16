from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..memory.models import EventCreate, PrivacyLevel, TrustLevel
from ..memory.store import MemoryStore
from ..storage import Storage
from .models import ActivityBatch, BrowserActivity

SENSITIVE_HOST_PARTS = {
    "auth",
    "bank",
    "banking",
    "card",
    "checkout",
    "finance",
    "login",
    "pay",
    "payment",
    "wallet",
}
SENSITIVE_PATH_SEGMENTS = {
    "auth",
    "authorize",
    "checkout",
    "login",
    "oauth",
    "password",
    "signin",
    "verify",
}
SENSITIVE_QUERY_KEYS = {
    "access_token",
    "auth",
    "authorization",
    "code",
    "id_token",
    "otp",
    "password",
    "refresh_token",
    "secret",
    "session",
    "token",
}


def _domain_matches(hostname: str, configured_domain: str) -> bool:
    candidate = configured_domain.lower().strip().lstrip(".")
    return bool(candidate) and (hostname == candidate or hostname.endswith(f".{candidate}"))


def sanitize_activity_url(url: str) -> tuple[str, str, str]:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port else ""
    origin = f"{parsed.scheme.lower()}://{hostname}{port}"
    clean_query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in SENSITIVE_QUERY_KEYS
    ]
    sanitized = urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path, urlencode(clean_query), "")
    )
    return sanitized, origin, hostname


@dataclass(frozen=True, slots=True)
class ActivityCaptureResult:
    accepted: int
    stored: int
    dropped: int
    origin_only: int
    disabled: bool = False


class ActivityCaptureService:
    def __init__(self, storage: Storage, memory: MemoryStore, *, user_id: str):
        self.storage = storage
        self.memory = memory
        self.user_id = user_id

    def status(self) -> dict[str, object]:
        return {
            "enabled": bool(self.storage.get_setting("activity_capture_enabled")),
            "blocked_domains": list(self.storage.get_setting("activity_blocked_domains")),
        }

    def update_settings(self, *, enabled: bool, blocked_domains: list[str]) -> dict[str, object]:
        normalized = sorted(
            {domain.lower().strip().lstrip(".") for domain in blocked_domains if domain.strip()}
        )
        self.storage.set_setting("activity_capture_enabled", enabled)
        self.storage.set_setting("activity_blocked_domains", normalized)
        return {"enabled": enabled, "blocked_domains": normalized}

    def capture(self, batch: ActivityBatch) -> ActivityCaptureResult:
        if not bool(self.storage.get_setting("activity_capture_enabled")):
            return ActivityCaptureResult(
                accepted=len(batch.events),
                stored=0,
                dropped=len(batch.events),
                origin_only=0,
                disabled=True,
            )
        blocked_domains = list(self.storage.get_setting("activity_blocked_domains"))
        stored = 0
        dropped = 0
        origin_only = 0
        for activity in batch.events:
            result = self._capture_one(activity, blocked_domains)
            if result is PrivacyLevel.DROP:
                dropped += 1
            else:
                stored += 1
                origin_only += int(result is PrivacyLevel.ORIGIN_ONLY)
        return ActivityCaptureResult(
            accepted=len(batch.events),
            stored=stored,
            dropped=dropped,
            origin_only=origin_only,
        )

    def _capture_one(self, activity: BrowserActivity, blocked_domains: list[str]) -> PrivacyLevel:
        sanitized_url, origin, hostname = sanitize_activity_url(activity.url)
        if any(_domain_matches(hostname, domain) for domain in blocked_domains):
            return PrivacyLevel.DROP
        privacy_level = (
            PrivacyLevel.ORIGIN_ONLY
            if self._is_sensitive(hostname, urlsplit(sanitized_url).path)
            else PrivacyLevel.STANDARD
        )
        content_parts = [activity.page_title]
        if activity.search_query:
            content_parts.append(activity.search_query)
        content = "\n".join(part for part in content_parts if part)
        source_reference = origin if privacy_level is PrivacyLevel.ORIGIN_ONLY else sanitized_url
        self.memory.append_event(
            user_id=self.user_id,
            event=EventCreate(
                event_type="browser.activity",
                source="safari_private" if activity.private_mode else activity.browser,
                content=content,
                payload={
                    "url": sanitized_url,
                    "origin": origin,
                    "domain": hostname,
                    "page_title": activity.page_title,
                    "search_query": activity.search_query,
                    "referrer_domain": activity.referrer_domain,
                    "estimated_dwell_time": activity.estimated_dwell_time,
                    "tab_session_id": activity.tab_session_id,
                    "private_mode": activity.private_mode,
                    "browser": activity.browser,
                },
                timestamp=activity.timestamp,
                device_id=activity.device_id,
                provenance={"collector": "safari_web_extension"},
                trust_level=TrustLevel.UNTRUSTED,
                source_reference=source_reference,
                privacy_level=privacy_level,
            ),
        )
        return privacy_level

    @staticmethod
    def _is_sensitive(hostname: str, path: str) -> bool:
        host_tokens = {
            token for label in hostname.split(".") for token in label.replace("-", "_").split("_")
        }
        path_segments = {segment.lower() for segment in path.split("/") if segment}
        return bool(host_tokens & SENSITIVE_HOST_PARTS or path_segments & SENSITIVE_PATH_SEGMENTS)
