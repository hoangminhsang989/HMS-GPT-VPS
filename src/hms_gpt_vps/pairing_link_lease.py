from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, urlsplit, urlunsplit

from .agent_package_transfer_attempt_factory import TransferTokenDpapiStore
from .pairing import PAIRING_SCHEMA_VERSION, PairingGrant, PairingRecord


PAIRING_LINK_LEASE_SCHEMA_VERSION = 1
_MAX_PAIRING_LINK_LEASE_BYTES = 64 * 1024
_PAIRING_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "pair_id",
        "instance_id",
        "token_sha256",
        "scopes",
        "issued_at",
        "expires_at",
        "consumed_at",
        "revoked_at",
    }
)


class PairingLinkLeaseError(RuntimeError):
    pass


class TextSecretStore(Protocol):
    def save_text(self, secret: str) -> None: ...
    def load_text(self) -> str: ...
    def clear(self) -> None: ...


def normalize_pairing_bridge_base_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url:
        raise PairingLinkLeaseError("Bridge base URL is required")
    parsed = urlsplit(base_url)
    if parsed.scheme != "https":
        raise PairingLinkLeaseError("Bridge base URL must use HTTPS")
    if not parsed.hostname:
        raise PairingLinkLeaseError("Bridge base URL requires a hostname")
    if parsed.username or parsed.password:
        raise PairingLinkLeaseError("Bridge base URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise PairingLinkLeaseError("Bridge base URL must not contain query or fragment")
    clean_path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, clean_path, "", ""))


def _expected_pairing_link(base_url: str, pair_id: str, token: str) -> str:
    if not isinstance(pair_id, str) or not pair_id:
        raise PairingLinkLeaseError("pair_id is required")
    if not isinstance(token, str) or not token:
        raise PairingLinkLeaseError("pairing token is required")
    base = normalize_pairing_bridge_base_url(base_url)
    return (
        f"{base}/pair/{quote(pair_id, safe='')}"
        f"#token={quote(token, safe='-_')}"
    )


def _strict_json_object(text: str) -> dict[str, object]:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PairingLinkLeaseError(f"duplicate pairing lease JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        raise PairingLinkLeaseError("pairing link lease is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PairingLinkLeaseError("pairing link lease must be a JSON object")
    return value


def _validate_record_mapping(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise PairingLinkLeaseError("pairing lease record must be an object")
    if frozenset(raw) != _PAIRING_RECORD_FIELDS:
        raise PairingLinkLeaseError("pairing lease record schema is invalid")
    schema = raw["schema_version"]
    if isinstance(schema, bool) or not isinstance(schema, int):
        raise PairingLinkLeaseError("pairing lease record schema_version must be an integer")
    if schema != PAIRING_SCHEMA_VERSION:
        raise PairingLinkLeaseError("pairing lease record schema_version mismatch")
    for key in ("pair_id", "instance_id", "token_sha256", "issued_at", "expires_at"):
        if not isinstance(raw[key], str) or not raw[key]:
            raise PairingLinkLeaseError(f"pairing lease record {key} must be a non-empty string")
    scopes = raw["scopes"]
    if not isinstance(scopes, list) or not scopes or any(
        not isinstance(item, str) or not item for item in scopes
    ):
        raise PairingLinkLeaseError("pairing lease record scopes must be strings")
    if raw["consumed_at"] is not None or raw["revoked_at"] is not None:
        raise PairingLinkLeaseError("pairing link lease must contain the initial active record")
    return raw


@dataclass(frozen=True)
class PairingLinkLease:
    record: PairingRecord
    bridge_base_url: str
    token: str = field(repr=False)
    pairing_link: str = field(repr=False)
    schema_version: int = PAIRING_LINK_LEASE_SCHEMA_VERSION

    def validate(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != PAIRING_LINK_LEASE_SCHEMA_VERSION
        ):
            raise PairingLinkLeaseError("unsupported pairing link lease schema")
        self.record.validate()
        if self.record.consumed_at is not None or self.record.revoked_at is not None:
            raise PairingLinkLeaseError("pairing link lease record must be initially active")
        if not isinstance(self.token, str) or not self.token:
            raise PairingLinkLeaseError("pairing link lease token is required")
        digest = hashlib.sha256(self.token.encode("utf-8")).hexdigest()
        if digest != self.record.token_sha256:
            raise PairingLinkLeaseError("pairing link lease token digest mismatch")
        normalized_base = normalize_pairing_bridge_base_url(self.bridge_base_url)
        if normalized_base != self.bridge_base_url:
            raise PairingLinkLeaseError("pairing link lease Bridge URL is not canonical")
        expected = _expected_pairing_link(
            self.bridge_base_url,
            self.record.pair_id,
            self.token,
        )
        if self.pairing_link != expected:
            raise PairingLinkLeaseError("pairing link lease URL differs from token authority")

    @classmethod
    def from_grant(cls, grant: PairingGrant, bridge_base_url: str) -> "PairingLinkLease":
        lease = cls(
            record=grant.record,
            bridge_base_url=normalize_pairing_bridge_base_url(bridge_base_url),
            token=grant.token,
            pairing_link=grant.pairing_link,
        )
        lease.validate()
        return lease

    def to_json(self) -> str:
        self.validate()
        payload = {
            "schema_version": self.schema_version,
            "record": self.record.to_dict(),
            "bridge_base_url": self.bridge_base_url,
            "token": self.token,
            "pairing_link": self.pairing_link,
        }
        text = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(text.encode("utf-8")) > _MAX_PAIRING_LINK_LEASE_BYTES:
            raise PairingLinkLeaseError("pairing link lease exceeds size bound")
        return text

    @classmethod
    def from_json(cls, text: str) -> "PairingLinkLease":
        if not isinstance(text, str) or not text:
            raise PairingLinkLeaseError("pairing link lease text is required")
        if len(text.encode("utf-8")) > _MAX_PAIRING_LINK_LEASE_BYTES:
            raise PairingLinkLeaseError("pairing link lease exceeds size bound")
        raw = _strict_json_object(text)
        if frozenset(raw) != frozenset(
            {"schema_version", "record", "bridge_base_url", "token", "pairing_link"}
        ):
            raise PairingLinkLeaseError("pairing link lease schema is invalid")
        schema = raw["schema_version"]
        if isinstance(schema, bool) or not isinstance(schema, int):
            raise PairingLinkLeaseError("pairing link lease schema_version must be an integer")
        record_raw = _validate_record_mapping(raw["record"])
        try:
            record = PairingRecord.from_dict(record_raw)
        except ValueError as exc:
            raise PairingLinkLeaseError("pairing link lease record failed validation") from exc
        bridge = raw["bridge_base_url"]
        token = raw["token"]
        link = raw["pairing_link"]
        if not isinstance(bridge, str) or not isinstance(token, str) or not isinstance(link, str):
            raise PairingLinkLeaseError("pairing link lease secret fields must be strings")
        lease = cls(
            schema_version=schema,
            record=record,
            bridge_base_url=bridge,
            token=token,
            pairing_link=link,
        )
        lease.validate()
        return lease


class PairingLinkLeaseStore:
    """Encrypted-at-rest holder for the recoverable raw one-time pairing URL."""

    def __init__(self, secret_store: TextSecretStore) -> None:
        self.secret_store = secret_store

    def save(self, lease: PairingLinkLease) -> None:
        self.secret_store.save_text(lease.to_json())

    def load(self) -> PairingLinkLease | None:
        try:
            text = self.secret_store.load_text()
        except FileNotFoundError:
            return None
        return PairingLinkLease.from_json(text)

    def clear(self) -> None:
        self.secret_store.clear()


def create_dpapi_pairing_link_lease_store(path: Path) -> PairingLinkLeaseStore:
    """Use the existing pinned current-user DPAPI file mechanics for pairing lease bytes."""
    return PairingLinkLeaseStore(TransferTokenDpapiStore(path))
