from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ..config import Settings
from ..storage import Storage, utc_now


class StrongAuthUnavailable(RuntimeError):
    pass


class StrongAuthRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticationOutcome:
    purpose: str
    credential_id: str
    approval: dict[str, Any] | None = None
    session_token: str | None = None
    session_expires_at: str | None = None


class StrongAuthService:
    cookie_name = "pa_passkey_session"
    max_challenge_attempts = 5

    def __init__(self, storage: Storage, settings: Settings) -> None:
        self.storage = storage
        self.user_id = settings.user_id
        self.rp_id = settings.webauthn_rp_id
        self.origin = settings.webauthn_origin
        self.rp_name = settings.webauthn_rp_name
        self.challenge_ttl_seconds = settings.webauthn_challenge_ttl_seconds
        self.session_ttl_hours = settings.webauthn_session_ttl_hours
        if self.configured:
            settings.validate_webauthn()
        self.purge_expired()

    @property
    def configured(self) -> bool:
        return bool(self.rp_id and self.origin)

    @property
    def secure_cookie(self) -> bool:
        return self.origin.startswith("https://")

    def status(self, session_token: str | None = None) -> dict[str, Any]:
        session = self.authenticate_session(session_token) if session_token else None
        return {
            "configured": self.configured,
            "rp_id": self.rp_id or None,
            "origin": self.origin or None,
            "credential_count": self.credential_count(),
            "authenticated": session is not None,
            "session_credential_id": session["credential_id"] if session else None,
            "strong_approval_available": self.configured and self.credential_count() > 0,
        }

    def credential_count(self) -> int:
        with self.storage.read_connection() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM webauthn_credentials "
                    "WHERE user_id=? AND revoked_at IS NULL",
                    (self.user_id,),
                ).fetchone()[0]
            )

    def list_credentials(self) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT credential_id, label, transports_json, device_type, backed_up, "
                "aaguid, created_at, last_used_at FROM webauthn_credentials "
                "WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at",
                (self.user_id,),
            ).fetchall()
        return [
            {
                **dict(row),
                "transports": json.loads(row["transports_json"]),
                "backed_up": bool(row["backed_up"]),
            }
            for row in rows
        ]

    def registration_options(self, label: str) -> dict[str, Any]:
        self._require_configured()
        normalized_label = " ".join(label.split())
        if not 1 <= len(normalized_label) <= 80:
            raise StrongAuthRejected("Passkey label must contain 1 to 80 characters")
        challenge = secrets.token_bytes(32)
        challenge_id = self._store_challenge(
            challenge=challenge,
            purpose="registration",
            binding=self._binding(
                "registration",
                {"user_id": self.user_id, "label": normalized_label},
            ),
            label=normalized_label,
        )
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=self.user_id.encode(),
            user_name=self.user_id,
            user_display_name="Personal Agent Owner",
            challenge=challenge,
            timeout=self.challenge_ttl_seconds * 1_000,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                require_resident_key=True,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=self._credential_descriptors(),
        )
        return {"challenge_id": challenge_id, "public_key": json.loads(options_to_json(options))}

    def verify_registration(self, challenge_id: str, credential: dict[str, Any]) -> dict[str, Any]:
        challenge = self._active_challenge(challenge_id, expected_purpose="registration")
        expected_binding = self._binding(
            "registration",
            {"user_id": self.user_id, "label": challenge["label"]},
        )
        if not secrets.compare_digest(challenge["binding_hash"], expected_binding):
            raise StrongAuthRejected("Registration binding does not match")
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=bytes(challenge["challenge"]),
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                require_user_presence=True,
                require_user_verification=True,
            )
        except (WebAuthnException, KeyError, TypeError, ValueError) as exc:
            self._record_failed_attempt(challenge_id)
            raise StrongAuthRejected("Passkey registration could not be verified") from exc
        if not verification.user_verified:
            self._record_failed_attempt(challenge_id)
            raise StrongAuthRejected("Passkey registration did not verify the user")

        credential_id = bytes_to_base64url(verification.credential_id)
        response = credential.get("response") if isinstance(credential, dict) else None
        raw_transports = response.get("transports", []) if isinstance(response, dict) else []
        transports = [item.value for item in AuthenticatorTransport if item.value in raw_transports]
        now = utc_now()
        try:
            with self.storage.transaction() as connection:
                self._consume_challenge(connection, challenge_id, now)
                connection.execute(
                    "INSERT INTO webauthn_credentials "
                    "(credential_id, user_id, label, public_key, sign_count, transports_json, "
                    "device_type, backed_up, aaguid, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        credential_id,
                        self.user_id,
                        challenge["label"],
                        verification.credential_public_key,
                        verification.sign_count,
                        json.dumps(transports),
                        verification.credential_device_type.value,
                        int(verification.credential_backed_up),
                        verification.aaguid,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise StrongAuthRejected("This passkey is already registered") from exc
        return {
            "credential_id": credential_id,
            "label": challenge["label"],
            "device_type": verification.credential_device_type.value,
            "backed_up": verification.credential_backed_up,
            "user_verified": verification.user_verified,
        }

    def login_options(self) -> dict[str, Any]:
        self._require_credentials()
        return self._authentication_options(purpose="login", binding={"user_id": self.user_id})

    def approval_options(self, approval_id: str) -> dict[str, Any]:
        self._require_credentials()
        approval = self.storage.get_approval(approval_id)
        if approval["state"] != "pending":
            raise StrongAuthRejected("Approval is no longer pending")
        binding = self._approval_binding(approval)
        result = self._authentication_options(
            purpose="approval",
            binding=binding,
            approval_id=approval_id,
        )
        result["approval"] = {
            key: approval[key]
            for key in (
                "approval_id",
                "task_id",
                "tool_name",
                "arguments_hash",
                "input_summary",
                "risk_level",
                "reason",
            )
        }
        return result

    def verify_authentication(
        self, challenge_id: str, credential: dict[str, Any]
    ) -> AuthenticationOutcome:
        challenge = self._active_challenge(challenge_id)
        credential_id = self._credential_id_from_response(credential)
        stored = self._credential(credential_id)
        expected_binding = self._expected_challenge_binding(challenge)
        if not secrets.compare_digest(challenge["binding_hash"], expected_binding):
            raise StrongAuthRejected("Authentication binding does not match")
        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=bytes(challenge["challenge"]),
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=bytes(stored["public_key"]),
                credential_current_sign_count=int(stored["sign_count"]),
                require_user_verification=True,
            )
        except (WebAuthnException, KeyError, TypeError, ValueError) as exc:
            self._record_failed_attempt(challenge_id)
            raise StrongAuthRejected("Passkey authentication could not be verified") from exc
        if not verification.user_verified:
            self._record_failed_attempt(challenge_id)
            raise StrongAuthRejected("Passkey authentication did not verify the user")
        verified_id = bytes_to_base64url(verification.credential_id)
        if not secrets.compare_digest(verified_id, credential_id):
            self._record_failed_attempt(challenge_id)
            raise StrongAuthRejected("Passkey credential does not match")

        now = utc_now()
        purpose = str(challenge["purpose"])
        session_token = None
        session_expires_at = None
        approval = None
        with self.storage.transaction() as connection:
            self._consume_challenge(connection, challenge_id, now)
            connection.execute(
                "UPDATE webauthn_credentials SET sign_count=?, last_used_at=?, "
                "device_type=?, backed_up=? WHERE credential_id=? AND revoked_at IS NULL",
                (
                    verification.new_sign_count,
                    now,
                    verification.credential_device_type.value,
                    int(verification.credential_backed_up),
                    credential_id,
                ),
            )
            if purpose == "login":
                session_token = secrets.token_urlsafe(48)
                session_hash = self._token_hash(session_token)
                session_expires_at = (
                    datetime.now(UTC) + timedelta(hours=self.session_ttl_hours)
                ).isoformat(timespec="milliseconds")
                connection.execute(
                    "INSERT INTO webauthn_sessions "
                    "(session_hash, user_id, credential_id, expires_at, created_at, last_seen_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        session_hash,
                        self.user_id,
                        credential_id,
                        session_expires_at,
                        now,
                        now,
                    ),
                )
            elif purpose == "approval":
                approval = self._approve_bound_action(connection, challenge, now)
            else:
                raise StrongAuthRejected("Unsupported authentication purpose")
        return AuthenticationOutcome(
            purpose=purpose,
            credential_id=credential_id,
            approval=approval,
            session_token=session_token,
            session_expires_at=session_expires_at,
        )

    def authenticate_session(self, token: str | None) -> dict[str, Any] | None:
        if not token or len(token) > 512:
            return None
        now = utc_now()
        with self.storage.transaction() as connection:
            row = connection.execute(
                "SELECT sessions.user_id, sessions.credential_id, sessions.expires_at "
                "FROM webauthn_sessions AS sessions "
                "JOIN webauthn_credentials AS credentials USING(credential_id) "
                "WHERE sessions.session_hash=? AND sessions.revoked_at IS NULL "
                "AND sessions.expires_at>? AND credentials.revoked_at IS NULL",
                (self._token_hash(token), now),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE webauthn_sessions SET last_seen_at=? WHERE session_hash=?",
                (now, self._token_hash(token)),
            )
        return dict(row)

    def logout(self, token: str | None) -> bool:
        if not token:
            return False
        with self.storage.transaction() as connection:
            cursor = connection.execute(
                "UPDATE webauthn_sessions SET revoked_at=? "
                "WHERE session_hash=? AND revoked_at IS NULL",
                (utc_now(), self._token_hash(token)),
            )
        return cursor.rowcount == 1

    def revoke_credential(self, credential_id: str) -> dict[str, Any]:
        now = utc_now()
        with self.storage.transaction() as connection:
            active = int(
                connection.execute(
                    "SELECT COUNT(*) FROM webauthn_credentials "
                    "WHERE user_id=? AND revoked_at IS NULL",
                    (self.user_id,),
                ).fetchone()[0]
            )
            if active <= 1:
                raise StrongAuthRejected(
                    "The last passkey cannot be revoked; register a backup passkey first"
                )
            cursor = connection.execute(
                "UPDATE webauthn_credentials SET revoked_at=? "
                "WHERE credential_id=? AND user_id=? AND revoked_at IS NULL",
                (now, credential_id, self.user_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(credential_id)
            connection.execute(
                "UPDATE webauthn_sessions SET revoked_at=? "
                "WHERE credential_id=? AND revoked_at IS NULL",
                (now, credential_id),
            )
        return {"credential_id": credential_id, "status": "revoked"}

    def purge_expired(self) -> None:
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "DELETE FROM webauthn_challenges WHERE expires_at<? OR consumed_at IS NOT NULL",
                (now,),
            )
            connection.execute(
                "DELETE FROM webauthn_sessions WHERE expires_at<? OR revoked_at IS NOT NULL",
                (now,),
            )

    def _authentication_options(
        self,
        *,
        purpose: str,
        binding: dict[str, Any],
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        challenge = secrets.token_bytes(32)
        challenge_id = self._store_challenge(
            challenge=challenge,
            purpose=purpose,
            binding=self._binding(purpose, binding),
            approval_id=approval_id,
        )
        options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge,
            timeout=self.challenge_ttl_seconds * 1_000,
            allow_credentials=self._credential_descriptors(),
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return {"challenge_id": challenge_id, "public_key": json.loads(options_to_json(options))}

    def _credential_descriptors(self) -> list[PublicKeyCredentialDescriptor]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT credential_id, transports_json FROM webauthn_credentials "
                "WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at",
                (self.user_id,),
            ).fetchall()
        descriptors = []
        for row in rows:
            transports = []
            for value in json.loads(row["transports_json"]):
                try:
                    transports.append(AuthenticatorTransport(value))
                except ValueError:
                    continue
            descriptors.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(row["credential_id"]),
                    transports=transports or None,
                )
            )
        return descriptors

    def _store_challenge(
        self,
        *,
        challenge: bytes,
        purpose: str,
        binding: str,
        approval_id: str | None = None,
        label: str | None = None,
    ) -> str:
        challenge_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        expires_at = (now + timedelta(seconds=self.challenge_ttl_seconds)).isoformat(
            timespec="milliseconds"
        )
        with self.storage.transaction() as connection:
            now_text = now.isoformat(timespec="milliseconds")
            connection.execute(
                "DELETE FROM webauthn_challenges WHERE expires_at<? OR consumed_at IS NOT NULL",
                (now_text,),
            )
            active = int(
                connection.execute(
                    "SELECT COUNT(*) FROM webauthn_challenges "
                    "WHERE user_id=? AND purpose=? AND consumed_at IS NULL AND expires_at>?",
                    (self.user_id, purpose, now_text),
                ).fetchone()[0]
            )
            if active >= 10:
                raise StrongAuthRejected("Too many active WebAuthn challenges")
            connection.execute(
                "INSERT INTO webauthn_challenges "
                "(challenge_id, challenge, purpose, user_id, approval_id, binding_hash, "
                "label, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    challenge_id,
                    challenge,
                    purpose,
                    self.user_id,
                    approval_id,
                    binding,
                    label,
                    expires_at,
                    now_text,
                ),
            )
        return challenge_id

    def _active_challenge(
        self, challenge_id: str, expected_purpose: str | None = None
    ) -> dict[str, Any]:
        self._require_configured()
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM webauthn_challenges WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
        if row is None:
            raise StrongAuthRejected("WebAuthn challenge was not found")
        result = dict(row)
        if result["consumed_at"] is not None:
            raise StrongAuthRejected("WebAuthn challenge has already been used")
        if result["expires_at"] <= utc_now():
            raise StrongAuthRejected("WebAuthn challenge has expired")
        if int(result["attempts"]) >= self.max_challenge_attempts:
            raise StrongAuthRejected("WebAuthn challenge attempt limit reached")
        if expected_purpose and result["purpose"] != expected_purpose:
            raise StrongAuthRejected("WebAuthn challenge purpose does not match")
        return result

    def _credential(self, credential_id: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM webauthn_credentials "
                "WHERE credential_id=? AND user_id=? AND revoked_at IS NULL",
                (credential_id, self.user_id),
            ).fetchone()
        if row is None:
            raise StrongAuthRejected("Passkey is not registered or has been revoked")
        return dict(row)

    @staticmethod
    def _credential_id_from_response(credential: dict[str, Any]) -> str:
        raw = credential.get("id")
        if not isinstance(raw, str) or not raw:
            raise StrongAuthRejected("Passkey response is missing a credential ID")
        try:
            return bytes_to_base64url(base64url_to_bytes(raw))
        except ValueError as exc:
            raise StrongAuthRejected("Passkey credential ID is invalid") from exc

    def _expected_challenge_binding(self, challenge: dict[str, Any]) -> str:
        purpose = challenge["purpose"]
        if purpose == "login":
            return self._binding("login", {"user_id": self.user_id})
        if purpose == "approval":
            approval = self.storage.get_approval(challenge["approval_id"])
            return self._binding("approval", self._approval_binding(approval))
        raise StrongAuthRejected("Unsupported authentication purpose")

    @staticmethod
    def _approval_binding(approval: dict[str, Any]) -> dict[str, Any]:
        return {
            "approval_id": approval["approval_id"],
            "task_id": approval["task_id"],
            "tool_name": approval["tool_name"],
            "arguments_hash": approval["arguments_hash"],
            "input_summary": approval["input_summary"],
            "risk_level": approval["risk_level"],
            "reason": approval["reason"],
        }

    def _binding(self, purpose: str, payload: dict[str, Any]) -> str:
        encoded = json.dumps(
            {
                "purpose": purpose,
                "rp_id": self.rp_id,
                "origin": self.origin,
                "payload": payload,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()

    def _approve_bound_action(
        self, connection: sqlite3.Connection, challenge: dict[str, Any], now: str
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM approvals WHERE approval_id=?", (challenge["approval_id"],)
        ).fetchone()
        if row is None:
            raise StrongAuthRejected("Bound approval was not found")
        approval = self.storage._approval_from_row(row)
        if approval["state"] != "pending":
            raise StrongAuthRejected("Bound approval is no longer pending")
        expected = self._binding("approval", self._approval_binding(approval))
        if not secrets.compare_digest(challenge["binding_hash"], expected):
            raise StrongAuthRejected("Approval changed after Face ID confirmation")
        connection.execute(
            "UPDATE approvals SET state='approved', decision_actor=?, decision_method=?, "
            "decided_at=?, updated_at=? WHERE approval_id=? AND state='pending'",
            (
                "primary_user:passkey",
                "webauthn_uv",
                now,
                now,
                approval["approval_id"],
            ),
        )
        updated = connection.execute(
            "SELECT * FROM approvals WHERE approval_id=?", (approval["approval_id"],)
        ).fetchone()
        return self.storage._approval_from_row(updated)

    def _record_failed_attempt(self, challenge_id: str) -> None:
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE webauthn_challenges SET attempts=attempts+1, "
                "consumed_at=CASE WHEN attempts+1>=? THEN ? ELSE consumed_at END "
                "WHERE challenge_id=? AND consumed_at IS NULL",
                (self.max_challenge_attempts, now, challenge_id),
            )

    @staticmethod
    def _consume_challenge(connection: sqlite3.Connection, challenge_id: str, now: str) -> None:
        cursor = connection.execute(
            "UPDATE webauthn_challenges SET consumed_at=? "
            "WHERE challenge_id=? AND consumed_at IS NULL AND expires_at>?",
            (now, challenge_id, now),
        )
        if cursor.rowcount != 1:
            raise StrongAuthRejected("WebAuthn challenge is expired or already used")

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _require_configured(self) -> None:
        if not self.configured:
            raise StrongAuthUnavailable(
                "WebAuthn is not configured; set the exact HTTPS RP ID and origin"
            )

    def _require_credentials(self) -> None:
        self._require_configured()
        if self.credential_count() == 0:
            raise StrongAuthUnavailable("Register an iPhone or Windows passkey first")
