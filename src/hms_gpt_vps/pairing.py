from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from typing import Any, Iterable
from urllib.parse import quote, urlsplit, urlunsplit


PAIRING_SCHEMA_VERSION = 1
PAIR_TOKEN_BYTES = 32
DEFAULT_PAIR_TTL_SECONDS = 600
MAX_PAIR_TTL_SECONDS = 1800
PAIRABLE_SCOPES = frozenset(
    {
        "workspace.read",
        "workspace.write",
        "process.test",
        "git.status",
        "audit.read",
    }
)


class PairingError(ValueError):
    pass


class PairingNotYetValidError(PairingError):
    pass


class PairingExpiredError(PairingError):
    pass


class PairingConsumedError(PairingError):
    pass


class PairingRevokedError(PairingError):
    pass


class PairingTokenMismatchError(PairingError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PairingError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _require_aware_utc(value, "timestamp").isoformat().replace("+00:00", "Z")


def _parse_iso(value: object, name: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PairingError(f"{name} must be an ISO timestamp")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PairingError(f"{name} is not a valid ISO timestamp") from exc
    return _require_aware_utc(parsed, name)


def _validate_scope(scope: str) -> None:
    if scope not in PAIRABLE_SCOPES:
        raise PairingError(f"unsupported pairing scope: {scope}")


def _normalize_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    values = tuple(sorted(set(scopes)))
    if not values:
        raise PairingError("at least one pairing scope is required")
    for scope in values:
        _validate_scope(scope)
    return values


def _token_digest(token: str) -> str:
    if not token:
        raise PairingTokenMismatchError("pairing token is required")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validate_pair_id(pair_id: str) -> None:
    if not pair_id or len(pair_id) > 128:
        raise PairingError("pair_id is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in pair_id):
        raise PairingError("pair_id contains unsupported characters")


def _validate_bridge_base_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https":
        raise PairingError("pairing bridge URL must use HTTPS")
    if not parsed.hostname:
        raise PairingError("pairing bridge URL requires a hostname")
    if parsed.username or parsed.password:
        raise PairingError("pairing bridge URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise PairingError("pairing bridge base URL must not contain query or fragment")
    clean_path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, clean_path, "", ""))


@dataclass(frozen=True)
class PairingRecord:
    schema_version: int
    pair_id: str
    instance_id: str
    token_sha256: str
    scopes: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    revoked_at: datetime | None = None

    def validate(self) -> None:
        if self.schema_version != PAIRING_SCHEMA_VERSION:
            raise PairingError(f"unsupported pairing schema: {self.schema_version}")
        _validate_pair_id(self.pair_id)
        if not self.instance_id.strip():
            raise PairingError("instance_id is required")
        if len(self.token_sha256) != 64:
            raise PairingError("token_sha256 must contain 64 hex characters")
        try:
            int(self.token_sha256, 16)
        except ValueError as exc:
            raise PairingError("token_sha256 must be hexadecimal") from exc
        normalized = _normalize_scopes(self.scopes)
        if normalized != self.scopes:
            raise PairingError("pairing scopes must be unique and sorted")
        issued = _require_aware_utc(self.issued_at, "issued_at")
        expires = _require_aware_utc(self.expires_at, "expires_at")
        if expires <= issued:
            raise PairingError("expires_at must be after issued_at")
        if (expires - issued).total_seconds() > MAX_PAIR_TTL_SECONDS:
            raise PairingError("pairing TTL exceeds maximum")

        consumed = None
        if self.consumed_at is not None:
            consumed = _require_aware_utc(self.consumed_at, "consumed_at")
            if consumed < issued or consumed >= expires:
                raise PairingError("consumed_at must be within the pairing validity window")

        revoked = None
        if self.revoked_at is not None:
            revoked = _require_aware_utc(self.revoked_at, "revoked_at")
            if revoked < issued:
                raise PairingError("revoked_at must not precede issued_at")

        if consumed is not None and revoked is not None:
            raise PairingError("pairing record cannot be both consumed and revoked")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "pair_id": self.pair_id,
            "instance_id": self.instance_id,
            "token_sha256": self.token_sha256,
            "scopes": list(self.scopes),
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "consumed_at": _iso(self.consumed_at),
            "revoked_at": _iso(self.revoked_at),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PairingRecord":
        scopes_raw = payload.get("scopes")
        if not isinstance(scopes_raw, list) or not all(isinstance(item, str) for item in scopes_raw):
            raise PairingError("pairing scopes must be a list of strings")
        issued_at = _parse_iso(payload.get("issued_at"), "issued_at")
        expires_at = _parse_iso(payload.get("expires_at"), "expires_at")
        if issued_at is None or expires_at is None:
            raise PairingError("issued_at and expires_at are required")
        record = cls(
            schema_version=int(payload.get("schema_version", -1)),
            pair_id=str(payload.get("pair_id", "")),
            instance_id=str(payload.get("instance_id", "")),
            token_sha256=str(payload.get("token_sha256", "")),
            scopes=tuple(scopes_raw),
            issued_at=issued_at,
            expires_at=expires_at,
            consumed_at=_parse_iso(payload.get("consumed_at"), "consumed_at"),
            revoked_at=_parse_iso(payload.get("revoked_at"), "revoked_at"),
        )
        record.validate()
        return record


@dataclass(frozen=True)
class PairingGrant:
    record: PairingRecord
    token: str = field(repr=False)
    pairing_link: str = field(repr=False)


def issue_pairing_grant(
    instance_id: str,
    bridge_base_url: str,
    *,
    scopes: Iterable[str] = PAIRABLE_SCOPES,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_PAIR_TTL_SECONDS,
) -> PairingGrant:
    if not instance_id.strip():
        raise PairingError("instance_id is required")
    if not (60 <= ttl_seconds <= MAX_PAIR_TTL_SECONDS):
        raise PairingError("pairing TTL must be between 60 and 1800 seconds")
    issued_at = _require_aware_utc(now or utc_now(), "now")
    normalized_scopes = _normalize_scopes(scopes)
    pair_id = secrets.token_urlsafe(16)
    token = secrets.token_urlsafe(PAIR_TOKEN_BYTES)
    record = PairingRecord(
        schema_version=PAIRING_SCHEMA_VERSION,
        pair_id=pair_id,
        instance_id=instance_id,
        token_sha256=_token_digest(token),
        scopes=normalized_scopes,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
    )
    record.validate()
    base = _validate_bridge_base_url(bridge_base_url)
    pair_path = f"{base}/pair/{quote(pair_id, safe='')}"
    pairing_link = f"{pair_path}#token={quote(token, safe='-_')}"
    return PairingGrant(record=record, token=token, pairing_link=pairing_link)


def verify_pairing_token(
    record: PairingRecord,
    token: str,
    *,
    instance_id: str,
    now: datetime | None = None,
) -> None:
    record.validate()
    checked_at = _require_aware_utc(now or utc_now(), "now")
    if instance_id != record.instance_id:
        raise PairingTokenMismatchError("pairing instance mismatch")
    if record.revoked_at is not None:
        raise PairingRevokedError("pairing grant is revoked")
    if record.consumed_at is not None:
        raise PairingConsumedError("pairing grant is already consumed")
    if checked_at < record.issued_at:
        raise PairingNotYetValidError("pairing grant is not yet valid")
    if checked_at >= record.expires_at:
        raise PairingExpiredError("pairing grant has expired")
    actual = _token_digest(token)
    if not hmac.compare_digest(actual, record.token_sha256):
        raise PairingTokenMismatchError("pairing token mismatch")


def consume_pairing_record(
    record: PairingRecord,
    token: str,
    *,
    instance_id: str,
    now: datetime | None = None,
) -> PairingRecord:
    consumed_at = _require_aware_utc(now or utc_now(), "now")
    verify_pairing_token(record, token, instance_id=instance_id, now=consumed_at)
    consumed = replace(record, consumed_at=consumed_at)
    consumed.validate()
    return consumed


def revoke_pairing_record(
    record: PairingRecord,
    *,
    now: datetime | None = None,
) -> PairingRecord:
    record.validate()
    if record.consumed_at is not None:
        raise PairingConsumedError("consumed pairing grant cannot be revoked")
    if record.revoked_at is not None:
        return record
    revoked = replace(record, revoked_at=_require_aware_utc(now or utc_now(), "now"))
    revoked.validate()
    return revoked
