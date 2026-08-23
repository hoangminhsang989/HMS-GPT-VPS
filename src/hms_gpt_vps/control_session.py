from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from typing import Any, Iterable

from .pairing import PAIRABLE_SCOPES, PairingError, PairingRecord


SESSION_SCHEMA_VERSION = 1
SESSION_TOKEN_BYTES = 32
DEFAULT_SESSION_TTL_SECONDS = 3600
MAX_SESSION_TTL_SECONDS = 86400


class ControlSessionError(ValueError):
    pass


class ControlSessionExpiredError(ControlSessionError):
    pass


class ControlSessionRevokedError(ControlSessionError):
    pass


class ControlSessionTokenMismatchError(ControlSessionError):
    pass


class ControlSessionScopeError(ControlSessionError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ControlSessionError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _aware_utc(value, "timestamp").isoformat().replace("+00:00", "Z")


def _parse_iso(value: object, name: str, *, required: bool = False) -> datetime | None:
    if value is None:
        if required:
            raise ControlSessionError(f"{name} is required")
        return None
    if not isinstance(value, str):
        raise ControlSessionError(f"{name} must be an ISO timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ControlSessionError(f"{name} is not a valid ISO timestamp") from exc
    return _aware_utc(parsed, name)


def _validate_identifier(value: str, name: str) -> None:
    if not value or len(value) > 128:
        raise ControlSessionError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise ControlSessionError(f"{name} contains unsupported characters")


def _normalize_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    values = tuple(sorted(set(scopes)))
    if not values:
        raise ControlSessionScopeError("at least one session scope is required")
    for scope in values:
        if scope not in PAIRABLE_SCOPES:
            raise ControlSessionScopeError(f"unsupported session scope: {scope}")
    return values


def _digest(token: str) -> str:
    if not token:
        raise ControlSessionTokenMismatchError("session token is required")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ControlSessionRecord:
    schema_version: int
    session_id: str
    family_id: str
    instance_id: str
    token_sha256: str
    scopes: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    epoch: int = 1
    rotated_from: str | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    def validate(self) -> None:
        if self.schema_version != SESSION_SCHEMA_VERSION:
            raise ControlSessionError(f"unsupported session schema: {self.schema_version}")
        _validate_identifier(self.session_id, "session_id")
        _validate_identifier(self.family_id, "family_id")
        if not self.instance_id.strip():
            raise ControlSessionError("instance_id is required")
        if len(self.token_sha256) != 64:
            raise ControlSessionError("token_sha256 must contain 64 hex characters")
        try:
            int(self.token_sha256, 16)
        except ValueError as exc:
            raise ControlSessionError("token_sha256 must be hexadecimal") from exc
        normalized = _normalize_scopes(self.scopes)
        if normalized != self.scopes:
            raise ControlSessionScopeError("session scopes must be unique and sorted")
        issued = _aware_utc(self.issued_at, "issued_at")
        expires = _aware_utc(self.expires_at, "expires_at")
        if expires <= issued:
            raise ControlSessionError("expires_at must be after issued_at")
        if (expires - issued).total_seconds() > MAX_SESSION_TTL_SECONDS:
            raise ControlSessionError("session TTL exceeds maximum")
        if self.epoch < 1:
            raise ControlSessionError("session epoch must be positive")
        if self.rotated_from is not None:
            _validate_identifier(self.rotated_from, "rotated_from")
            if self.epoch <= 1:
                raise ControlSessionError("rotated sessions must have epoch greater than one")
        if self.revoked_at is not None:
            _aware_utc(self.revoked_at, "revoked_at")
            if not self.revocation_reason:
                raise ControlSessionError("revoked sessions require a revocation_reason")
        elif self.revocation_reason is not None:
            raise ControlSessionError("revocation_reason requires revoked_at")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "family_id": self.family_id,
            "instance_id": self.instance_id,
            "token_sha256": self.token_sha256,
            "scopes": list(self.scopes),
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "epoch": self.epoch,
            "rotated_from": self.rotated_from,
            "revoked_at": _iso(self.revoked_at),
            "revocation_reason": self.revocation_reason,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ControlSessionRecord":
        scopes_raw = payload.get("scopes")
        if not isinstance(scopes_raw, list) or not all(isinstance(item, str) for item in scopes_raw):
            raise ControlSessionError("session scopes must be a list of strings")
        issued_at = _parse_iso(payload.get("issued_at"), "issued_at", required=True)
        expires_at = _parse_iso(payload.get("expires_at"), "expires_at", required=True)
        assert issued_at is not None and expires_at is not None
        epoch_raw = payload.get("epoch")
        if not isinstance(epoch_raw, int) or isinstance(epoch_raw, bool):
            raise ControlSessionError("session epoch must be an integer")
        record = cls(
            schema_version=int(payload.get("schema_version", -1)),
            session_id=str(payload.get("session_id", "")),
            family_id=str(payload.get("family_id", "")),
            instance_id=str(payload.get("instance_id", "")),
            token_sha256=str(payload.get("token_sha256", "")),
            scopes=tuple(scopes_raw),
            issued_at=issued_at,
            expires_at=expires_at,
            epoch=epoch_raw,
            rotated_from=(
                str(payload["rotated_from"])
                if payload.get("rotated_from") is not None
                else None
            ),
            revoked_at=_parse_iso(payload.get("revoked_at"), "revoked_at"),
            revocation_reason=(
                str(payload["revocation_reason"])
                if payload.get("revocation_reason") is not None
                else None
            ),
        )
        record.validate()
        return record


@dataclass(frozen=True)
class ControlSessionGrant:
    record: ControlSessionRecord
    token: str = field(repr=False)


@dataclass(frozen=True)
class ControlSessionRotation:
    previous: ControlSessionRecord
    grant: ControlSessionGrant


def issue_control_session(
    pairing: PairingRecord,
    *,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    scopes: Iterable[str] | None = None,
) -> ControlSessionGrant:
    pairing.validate()
    if pairing.consumed_at is None:
        raise PairingError("pairing record must be consumed before issuing a session")
    if pairing.revoked_at is not None:
        raise PairingError("revoked pairing record cannot issue a session")
    if not (60 <= ttl_seconds <= MAX_SESSION_TTL_SECONDS):
        raise ControlSessionError("session TTL must be between 60 and 86400 seconds")
    issued_at = _aware_utc(now or utc_now(), "now")
    requested = _normalize_scopes(scopes if scopes is not None else pairing.scopes)
    if not set(requested).issubset(pairing.scopes):
        raise ControlSessionScopeError("session scopes cannot exceed pairing scopes")
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    record = ControlSessionRecord(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id=secrets.token_urlsafe(16),
        family_id=secrets.token_urlsafe(16),
        instance_id=pairing.instance_id,
        token_sha256=_digest(token),
        scopes=requested,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
    )
    record.validate()
    return ControlSessionGrant(record=record, token=token)


def verify_control_session(
    record: ControlSessionRecord,
    token: str,
    *,
    instance_id: str,
    required_scope: str,
    now: datetime | None = None,
) -> None:
    record.validate()
    checked_at = _aware_utc(now or utc_now(), "now")
    if instance_id != record.instance_id:
        raise ControlSessionTokenMismatchError("session instance mismatch")
    if record.revoked_at is not None:
        raise ControlSessionRevokedError("session is revoked")
    if checked_at >= record.expires_at:
        raise ControlSessionExpiredError("session has expired")
    if required_scope not in record.scopes:
        raise ControlSessionScopeError(f"session does not grant scope: {required_scope}")
    if not hmac.compare_digest(_digest(token), record.token_sha256):
        raise ControlSessionTokenMismatchError("session token mismatch")


def rotate_control_session(
    record: ControlSessionRecord,
    token: str,
    *,
    instance_id: str,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    scopes: Iterable[str] | None = None,
) -> ControlSessionRotation:
    rotated_at = _aware_utc(now or utc_now(), "now")
    # Rotation authentication requires one existing granted scope; every valid
    # session has at least one scope by construction.
    verify_control_session(
        record,
        token,
        instance_id=instance_id,
        required_scope=record.scopes[0],
        now=rotated_at,
    )
    if not (60 <= ttl_seconds <= MAX_SESSION_TTL_SECONDS):
        raise ControlSessionError("session TTL must be between 60 and 86400 seconds")
    next_scopes = _normalize_scopes(scopes if scopes is not None else record.scopes)
    if not set(next_scopes).issubset(record.scopes):
        raise ControlSessionScopeError("rotation cannot expand session scopes")

    previous = replace(
        record,
        revoked_at=rotated_at,
        revocation_reason="rotated",
    )
    previous.validate()
    next_token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    next_record = ControlSessionRecord(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id=secrets.token_urlsafe(16),
        family_id=record.family_id,
        instance_id=record.instance_id,
        token_sha256=_digest(next_token),
        scopes=next_scopes,
        issued_at=rotated_at,
        expires_at=rotated_at + timedelta(seconds=ttl_seconds),
        epoch=record.epoch + 1,
        rotated_from=record.session_id,
    )
    next_record.validate()
    return ControlSessionRotation(
        previous=previous,
        grant=ControlSessionGrant(record=next_record, token=next_token),
    )


def revoke_control_session(
    record: ControlSessionRecord,
    *,
    reason: str = "revoked",
    now: datetime | None = None,
) -> ControlSessionRecord:
    record.validate()
    if record.revoked_at is not None:
        return record
    if not reason.strip() or len(reason) > 128:
        raise ControlSessionError("revocation reason is invalid")
    revoked = replace(
        record,
        revoked_at=_aware_utc(now or utc_now(), "now"),
        revocation_reason=reason,
    )
    revoked.validate()
    return revoked
