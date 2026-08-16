from __future__ import annotations

from datetime import datetime
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator


class BrowserActivity(BaseModel):
    timestamp: datetime
    device_id: str = Field(min_length=1, max_length=256)
    browser: str = Field(default="safari", min_length=1, max_length=100)
    private_mode: bool = True
    url: str = Field(min_length=1, max_length=8_000)
    page_title: str = Field(default="", max_length=2_000)
    search_query: str | None = Field(default=None, max_length=2_000)
    referrer_domain: str | None = Field(default=None, max_length=500)
    estimated_dwell_time: float = Field(default=0, ge=0, le=86_400)
    tab_session_id: str = Field(min_length=1, max_length=256)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Activity URL must use http or https")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Activity URL has an invalid port") from exc
        return value


class ActivityBatch(BaseModel):
    events: list[BrowserActivity] = Field(min_length=1, max_length=500)


class ActivitySettingsUpdate(BaseModel):
    enabled: bool
    blocked_domains: list[str] = Field(default_factory=list, max_length=1_000)
