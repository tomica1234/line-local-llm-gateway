from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class SecretKind(StrEnum):
    USERNAME = "username"
    PASSWORD = "password"  # pragma: allowlist secret
    TOTP_SEED = "totp_seed"
    API_TOKEN = "api_token"


class SecretAction(StrEnum):
    USERNAME_FILL = "username_fill"
    PASSWORD_FILL = "password_fill"  # pragma: allowlist secret
    TOTP_FILL = "totp_fill"
    CONNECTOR_REQUEST = "connector_request"


class SecretCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(pattern=r"^secret://[a-z0-9][a-z0-9._/-]{2,200}$")
    kind: SecretKind
    account_label: str = Field(min_length=1, max_length=200)
    allowed_origins: list[str] = Field(min_length=1, max_length=100)
    allowed_actions: list[SecretAction] = Field(min_length=1, max_length=10)

    @field_validator("allowed_origins")
    @classmethod
    def origins_are_unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("allowed_origins must not contain duplicates")
        return value


class SecretMetadata(BaseModel):
    credential_id: str
    kind: SecretKind
    account_label: str
    allowed_origins: list[str]
    allowed_actions: list[SecretAction]
    enabled: bool
    created_at: str
    updated_at: str
    last_used_at: str | None = None


class SecretPutRequest(SecretCreate):
    """A write-only API payload; responses must always use SecretMetadata."""

    value: SecretStr
