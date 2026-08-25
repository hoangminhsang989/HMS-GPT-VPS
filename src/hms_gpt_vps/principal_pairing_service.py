from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
from typing import Protocol

from .agent_package_transfer_attempt_factory import TransferTokenDpapiStore
from .authority_lock import exclusive_authority_lock
from .control_session import ControlSessionGrant, ControlSessionRecord
from .control_session_store import ControlSessionNotFoundError
from .pairing import PAIRABLE_SCOPES
from .pairing_exchange import (
    PairingExchangeKey,
    PairingSessionExchange,
    derive_initial_session_grant,
)
from .pairing_link_lease import PairingLinkLease
from .pairing_readiness_runtime import PairingReadinessRuntime


PRINCIPAL_SESSION_BINDING_SCHEMA_VERSION = 1
_MAX_PRINCIPAL_BINDING_BYTES = 64 * 1024
_MAX_PAIRING_LINK_CHARS = 4096
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_HEX_LOWER = frozenset("0123456789abcdef")
_PRINCIPAL_NONCE_DOMAIN = b"hms-gpt-vps/principal-pairing-nonce/v1"
_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "principal_sha256",
        "instance_id",
        "pair_id",
        "session_id",
        "family_id",
        "session_token_sha256",
        "scopes",
        "issued_at",
        "expires_at",
        "epoch",
        "session_token",
    }
)


class PrincipalPairingError(RuntimeError):
    pass


class PrincipalPairingUnavailableError(PrincipalPairingError):
    pass


class PrincipalPairingRejectedError(PrincipalPairingError):
    pass


class PrincipalPairingConflictError(PrincipalPairingError):
    pass


class PrincipalBindingError(PrincipalPairingError):
    pass


class TextSecretStore(Protocol):
    def save_text(self, secret: str) -> None: ...
    def load_text(self) -> str: ...


class PrincipalBindingRegistry(Protocol):
    def store_for(
        self,
        principal_sha256: str,
        instance_id: str,
    ) -> "PrincipalSessionBindingStore": ...


def _aware_utc(value: datetime, name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise PrincipalBindingError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware_utc(value, "binding timestamp").isoformat().replace(
        "+00:00",
        "Z",
    )


def _parse_iso(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PrincipalBindingError(f"{name} must be a timestamp string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PrincipalBindingError(f"{name} is not a valid timestamp") from exc
    parsed = _aware_utc(parsed, name)
    if _iso(parsed) != value:
        raise PrincipalBindingError(f"{name} must be canonical UTC")
    return parsed


def _canonical_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in _HEX_LOWER for char in value)
    ):
        raise PrincipalBindingError(
            f"{name} must be canonical lowercase SHA-256"
        )
    return value


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise PrincipalBindingError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise PrincipalBindingError(f"{name} contains unsupported characters")
    return value


def _instance_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 128
    ):
        raise PrincipalBindingError("instance_id is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PrincipalBindingError("instance_id contains control characters")
    return value


def _strict_json_object(text: str) -> dict[str, object]:
    def no_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PrincipalBindingError(
                    f"principal binding has duplicate JSON key: {key}"
                )
            result[key] = value
        return result

    if not isinstance(text, str) or not text:
        raise PrincipalBindingError("principal binding text is required")
    encoded = text.encode("utf-8")
    if len(encoded) > _MAX_PRINCIPAL_BINDING_BYTES:
        raise PrincipalBindingError("principal binding exceeds size bound")
    try:
        value = json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        raise PrincipalBindingError(
            "principal binding is not valid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise PrincipalBindingError(
            "principal binding must be a JSON object"
        )
    return value


def _path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = path.expanduser().absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            return True
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = int(getattr(info, "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    return False


@dataclass(frozen=True)
class TrustedIntegrationPrincipal:
    """Identity produced by the authenticated app/MCP boundary, not model input."""

    namespace: str
    subject: str = field(repr=False)

    def validate(self) -> None:
        if (
            not isinstance(self.namespace, str)
            or not self.namespace.strip()
            or self.namespace != self.namespace.strip()
            or len(self.namespace) > 128
        ):
            raise PrincipalPairingError("principal namespace is invalid")
        if (
            not isinstance(self.subject, str)
            or not self.subject.strip()
            or self.subject != self.subject.strip()
            or len(self.subject) > 512
        ):
            raise PrincipalPairingError("principal subject is invalid")
        for value, name in (
            (self.namespace, "namespace"),
            (self.subject, "subject"),
        ):
            if any(
                ord(char) < 0x20 or ord(char) == 0x7F
                for char in value
            ):
                raise PrincipalPairingError(
                    f"principal {name} contains control characters"
                )

    def sha256(self) -> str:
        self.validate()
        raw = json.dumps(
            {
                "namespace": self.namespace,
                "subject": self.subject,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(
            b"hms-gpt-vps/integration-principal/v1\x00" + raw
        ).hexdigest()


@dataclass(frozen=True)
class PrincipalSessionBinding:
    schema_version: int
    principal_sha256: str
    instance_id: str
    pair_id: str
    session_id: str
    family_id: str
    session_token_sha256: str
    scopes: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    epoch: int
    session_token: str = field(repr=False)

    def validate(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != PRINCIPAL_SESSION_BINDING_SCHEMA_VERSION
        ):
            raise PrincipalBindingError(
                "unsupported principal binding schema"
            )
        _canonical_sha256(
            self.principal_sha256,
            "principal_sha256",
        )
        _instance_id(self.instance_id)
        _identifier(self.pair_id, "pair_id")
        _identifier(self.session_id, "session_id")
        _identifier(self.family_id, "family_id")
        _canonical_sha256(
            self.session_token_sha256,
            "session_token_sha256",
        )
        if not isinstance(self.scopes, tuple) or not self.scopes:
            raise PrincipalBindingError(
                "binding scopes must be a non-empty tuple"
            )
        if (
            any(
                not isinstance(scope, str)
                or scope not in PAIRABLE_SCOPES
                for scope in self.scopes
            )
            or tuple(sorted(set(self.scopes))) != self.scopes
        ):
            raise PrincipalBindingError(
                "binding scopes must be canonical and supported"
            )
        issued = _aware_utc(self.issued_at, "issued_at")
        expires = _aware_utc(self.expires_at, "expires_at")
        if expires <= issued:
            raise PrincipalBindingError(
                "binding expires_at must follow issued_at"
            )
        if (
            isinstance(self.epoch, bool)
            or not isinstance(self.epoch, int)
            or self.epoch < 1
        ):
            raise PrincipalBindingError(
                "binding epoch must be a positive integer"
            )
        if (
            not isinstance(self.session_token, str)
            or not self.session_token
            or len(self.session_token) > 512
        ):
            raise PrincipalBindingError("binding session token is invalid")
        digest = hashlib.sha256(
            self.session_token.encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(
            digest,
            self.session_token_sha256,
        ):
            raise PrincipalBindingError(
                "binding session token digest mismatch"
            )

    @classmethod
    def from_grant(
        cls,
        principal_sha256: str,
        pair_id: str,
        grant: ControlSessionGrant,
    ) -> "PrincipalSessionBinding":
        record = grant.record
        record.validate()
        binding = cls(
            schema_version=PRINCIPAL_SESSION_BINDING_SCHEMA_VERSION,
            principal_sha256=principal_sha256,
            instance_id=record.instance_id,
            pair_id=pair_id,
            session_id=record.session_id,
            family_id=record.family_id,
            session_token_sha256=record.token_sha256,
            scopes=record.scopes,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
            epoch=record.epoch,
            session_token=grant.token,
        )
        binding.validate()
        return binding

    def to_json(self) -> str:
        self.validate()
        payload = {
            "schema_version": self.schema_version,
            "principal_sha256": self.principal_sha256,
            "instance_id": self.instance_id,
            "pair_id": self.pair_id,
            "session_id": self.session_id,
            "family_id": self.family_id,
            "session_token_sha256": self.session_token_sha256,
            "scopes": list(self.scopes),
            "issued_at": _iso(self.issued_at),
            "expires_at": _iso(self.expires_at),
            "epoch": self.epoch,
            "session_token": self.session_token,
        }
        text = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(text.encode("utf-8")) > _MAX_PRINCIPAL_BINDING_BYTES:
            raise PrincipalBindingError(
                "principal binding exceeds size bound"
            )
        return text

    @classmethod
    def from_json(cls, text: str) -> "PrincipalSessionBinding":
        payload = _strict_json_object(text)
        if frozenset(payload) != _BINDING_FIELDS:
            raise PrincipalBindingError(
                "principal binding fields do not match schema"
            )
        schema = payload["schema_version"]
        epoch = payload["epoch"]
        scopes = payload["scopes"]
        if isinstance(schema, bool) or not isinstance(schema, int):
            raise PrincipalBindingError(
                "principal binding schema_version must be an integer"
            )
        if isinstance(epoch, bool) or not isinstance(epoch, int):
            raise PrincipalBindingError(
                "principal binding epoch must be an integer"
            )
        if (
            not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(scope, str) for scope in scopes)
        ):
            raise PrincipalBindingError(
                "principal binding scopes must be a list of strings"
            )
        for field_name in (
            "principal_sha256",
            "instance_id",
            "pair_id",
            "session_id",
            "family_id",
            "session_token_sha256",
            "issued_at",
            "expires_at",
            "session_token",
        ):
            if not isinstance(payload[field_name], str):
                raise PrincipalBindingError(
                    f"principal binding {field_name} must be a string"
                )
        binding = cls(
            schema_version=schema,
            principal_sha256=payload["principal_sha256"],
            instance_id=payload["instance_id"],
            pair_id=payload["pair_id"],
            session_id=payload["session_id"],
            family_id=payload["family_id"],
            session_token_sha256=payload["session_token_sha256"],
            scopes=tuple(scopes),
            issued_at=_parse_iso(payload["issued_at"], "issued_at"),
            expires_at=_parse_iso(payload["expires_at"], "expires_at"),
            epoch=epoch,
            session_token=payload["session_token"],
        )
        binding.validate()
        return binding


class PrincipalSessionBindingStore:
    def __init__(self, secret_store: TextSecretStore) -> None:
        self.secret_store = secret_store

    def load(self) -> PrincipalSessionBinding | None:
        try:
            text = self.secret_store.load_text()
        except FileNotFoundError:
            return None
        try:
            return PrincipalSessionBinding.from_json(text)
        except PrincipalBindingError:
            raise
        except Exception as exc:
            raise PrincipalBindingError(
                "principal binding secret store could not be decoded"
            ) from exc

    def save_exact(
        self,
        binding: PrincipalSessionBinding,
    ) -> PrincipalSessionBinding:
        binding.validate()
        existing = self.load()
        if existing is not None:
            if existing != binding:
                raise PrincipalPairingConflictError(
                    "principal binding already exists with different authority"
                )
            return existing
        self.secret_store.save_text(binding.to_json())
        readback = self.load()
        if readback is None or readback != binding:
            raise PrincipalBindingError(
                "principal binding readback differs from published authority"
            )
        return readback


class DpapiPrincipalBindingRegistry:
    """Per-principal/per-instance encrypted binding files in a trusted root."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().absolute()
        if _path_chain_has_redirect(self.root):
            raise PrincipalBindingError(
                "principal binding root traverses a link or reparse point"
            )
        if not self.root.exists() or not self.root.is_dir():
            raise PrincipalBindingError(
                "principal binding root must already be an existing directory"
            )

    def store_for(
        self,
        principal_sha256: str,
        instance_id: str,
    ) -> PrincipalSessionBindingStore:
        principal_digest = _canonical_sha256(
            principal_sha256,
            "principal_sha256",
        )
        checked_instance = _instance_id(instance_id)
        if _path_chain_has_redirect(self.root) or not self.root.is_dir():
            raise PrincipalBindingError(
                "principal binding root authority changed"
            )
        instance_digest = hashlib.sha256(
            checked_instance.encode("utf-8")
        ).hexdigest()
        path = self.root / (
            f"principal-{principal_digest}-instance-{instance_digest}.dpapi"
        )
        return PrincipalSessionBindingStore(
            TransferTokenDpapiStore(path)
        )


@dataclass(frozen=True)
class PrincipalPairingResult:
    instance_id: str
    session_id: str
    scopes: tuple[str, ...]
    expires_at: datetime

    def __post_init__(self) -> None:
        _instance_id(self.instance_id)
        _identifier(self.session_id, "session_id")
        if (
            not isinstance(self.scopes, tuple)
            or not self.scopes
            or tuple(sorted(set(self.scopes))) != self.scopes
            or any(scope not in PAIRABLE_SCOPES for scope in self.scopes)
        ):
            raise PrincipalPairingError(
                "principal pairing result scopes are invalid"
            )
        _aware_utc(self.expires_at, "expires_at")


def derive_principal_client_nonce(
    key: PairingExchangeKey,
    principal_sha256: str,
    pair_id: str,
) -> str:
    digest = _canonical_sha256(
        principal_sha256,
        "principal_sha256",
    )
    checked_pair_id = _identifier(pair_id, "pair_id")
    material = b"\x00".join(
        (
            _PRINCIPAL_NONCE_DOMAIN,
            digest.encode("ascii"),
            checked_pair_id.encode("ascii"),
        )
    )
    raw = hmac.new(key.value, material, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class PrincipalPairingService:
    """Bind one one-time pairing grant to an authenticated app/MCP principal.

    The model supplies only the copied pairing link. The authenticated
    integration layer supplies TrustedIntegrationPrincipal out-of-band. Raw
    session credentials are persisted only in the encrypted binding store and
    are never returned by PrincipalPairingResult.
    """

    def __init__(
        self,
        readiness: PairingReadinessRuntime,
        exchange: PairingSessionExchange,
        binding_registry: PrincipalBindingRegistry,
        lock_path: Path,
    ) -> None:
        if not isinstance(readiness, PairingReadinessRuntime):
            raise TypeError(
                "readiness must be a PairingReadinessRuntime"
            )
        if not isinstance(exchange, PairingSessionExchange):
            raise TypeError(
                "exchange must be a PairingSessionExchange"
            )
        if readiness.pairing_store is not exchange.pairing_store:
            raise PrincipalPairingError(
                "principal pairing requires readiness and exchange to share exact PairingStore"
            )
        self.readiness = readiness
        self.exchange = exchange
        self.binding_registry = binding_registry
        self.lock_path = lock_path.expanduser().absolute()

    @staticmethod
    def _result(
        binding: PrincipalSessionBinding,
    ) -> PrincipalPairingResult:
        binding.validate()
        return PrincipalPairingResult(
            instance_id=binding.instance_id,
            session_id=binding.session_id,
            scopes=binding.scopes,
            expires_at=binding.expires_at,
        )

    def _verify_binding_session(
        self,
        binding: PrincipalSessionBinding,
        *,
        now: datetime,
    ) -> ControlSessionRecord:
        binding.validate()
        record = self.exchange.session_store.require(
            binding.session_id
        )
        record.validate()
        if (
            record.instance_id != binding.instance_id
            or record.session_id != binding.session_id
            or record.family_id != binding.family_id
            or record.token_sha256 != binding.session_token_sha256
            or record.scopes != binding.scopes
            or record.issued_at != binding.issued_at
            or record.expires_at != binding.expires_at
            or record.epoch != binding.epoch
        ):
            raise PrincipalBindingError(
                "principal binding differs from durable session authority"
            )
        self.exchange.session_store.verify(
            binding.session_id,
            binding.session_token,
            instance_id=binding.instance_id,
            required_scope=binding.scopes[0],
            now=now,
        )
        return record

    def _recover_committed_grant(
        self,
        *,
        lease: PairingLinkLease,
        principal_sha256: str,
        now: datetime,
    ) -> ControlSessionGrant:
        current = self.exchange.pairing_store.require(
            lease.record.pair_id
        )
        if current.consumed_at is None:
            raise PrincipalPairingConflictError(
                "pairing is not durably consumed for internal recovery"
            )
        nonce = derive_principal_client_nonce(
            self.exchange.key,
            principal_sha256,
            current.pair_id,
        )
        grant = derive_initial_session_grant(
            current,
            lease.token,
            nonce,
            self.exchange.key,
        )
        try:
            stored = self.exchange.session_store.require(
                grant.record.session_id
            )
        except ControlSessionNotFoundError as exc:
            raise PrincipalPairingConflictError(
                "consumed pairing belongs to a different exchange authority"
            ) from exc
        if stored.to_dict() != grant.record.to_dict():
            raise PrincipalPairingConflictError(
                "consumed pairing belongs to a different exchange authority"
            )
        if now < stored.issued_at or now >= stored.expires_at:
            raise PrincipalPairingUnavailableError(
                "recovered principal session is not currently valid"
            )
        return grant

    def pair(
        self,
        principal: TrustedIntegrationPrincipal,
        pairing_link: str,
    ) -> PrincipalPairingResult:
        if not isinstance(principal, TrustedIntegrationPrincipal):
            raise TypeError(
                "principal must be a TrustedIntegrationPrincipal"
            )
        principal.validate()
        if (
            not isinstance(pairing_link, str)
            or not pairing_link
            or len(pairing_link) > _MAX_PAIRING_LINK_CHARS
        ):
            raise PrincipalPairingRejectedError(
                "pairing link is invalid"
            )
        principal_sha256 = principal.sha256()

        with exclusive_authority_lock(self.lock_path):
            now = self.readiness._now()
            before = self.readiness.observe()
            if (
                before.pairing_ready is not True
                or before.pair_id is None
            ):
                raise PrincipalPairingUnavailableError(
                    "pairing is not currently ready"
                )

            lease = self.readiness.lease_store.load()
            if lease is None:
                raise PrincipalPairingUnavailableError(
                    "pairing link authority is unavailable"
                )
            lease.validate()
            if (
                lease.record.instance_id
                != self.readiness.config.instance_id
                or lease.record.pair_id != before.pair_id
            ):
                raise PrincipalBindingError(
                    "pairing lease differs from readiness authority"
                )
            if not hmac.compare_digest(
                pairing_link.encode("utf-8"),
                lease.pairing_link.encode("utf-8"),
            ):
                raise PrincipalPairingRejectedError(
                    "pairing link does not match current authority"
                )

            store = self.binding_registry.store_for(
                principal_sha256,
                lease.record.instance_id,
            )
            existing = store.load()
            if existing is not None:
                if (
                    existing.principal_sha256 != principal_sha256
                    or existing.instance_id != lease.record.instance_id
                    or existing.pair_id != lease.record.pair_id
                ):
                    raise PrincipalPairingConflictError(
                        "existing principal binding belongs to different authority"
                    )
                if before.paired is not True:
                    raise PrincipalBindingError(
                        "principal binding exists but pairing is not consumed"
                    )
                self._verify_binding_session(
                    existing,
                    now=now,
                )
                return self._result(existing)

            if before.paired is True:
                grant = self._recover_committed_grant(
                    lease=lease,
                    principal_sha256=principal_sha256,
                    now=now,
                )
            else:
                nonce = derive_principal_client_nonce(
                    self.exchange.key,
                    principal_sha256,
                    lease.record.pair_id,
                )
                grant = self.exchange.exchange(
                    lease.record.pair_id,
                    lease.token,
                    nonce,
                    instance_id=lease.record.instance_id,
                    now=now,
                )

            after = self.readiness.observe()
            if (
                after.pairing_ready is not True
                or after.paired is not True
                or after.pair_id != lease.record.pair_id
            ):
                raise PrincipalPairingUnavailableError(
                    "pairing lost fresh Agent readiness after exchange"
                )

            binding = PrincipalSessionBinding.from_grant(
                principal_sha256,
                lease.record.pair_id,
                grant,
            )
            self._verify_binding_session(
                binding,
                now=self.readiness._now(),
            )
            published = store.save_exact(binding)
            if published != binding:
                raise PrincipalBindingError(
                    "published principal binding differs from session authority"
                )

            final = self.readiness.observe()
            if (
                final.pairing_ready is not True
                or final.paired is not True
                or final.pair_id != lease.record.pair_id
            ):
                raise PrincipalPairingUnavailableError(
                    "pairing lost fresh Agent readiness after binding publication"
                )
            return self._result(published)

    def load_active_binding(
        self,
        principal: TrustedIntegrationPrincipal,
        instance_id: str,
    ) -> PrincipalSessionBinding:
        if not isinstance(principal, TrustedIntegrationPrincipal):
            raise TypeError(
                "principal must be a TrustedIntegrationPrincipal"
            )
        principal.validate()
        checked_instance = _instance_id(instance_id)
        principal_sha256 = principal.sha256()
        store = self.binding_registry.store_for(
            principal_sha256,
            checked_instance,
        )
        binding = store.load()
        if binding is None:
            raise PrincipalPairingUnavailableError(
                "principal has no bound control session"
            )
        if (
            binding.principal_sha256 != principal_sha256
            or binding.instance_id != checked_instance
        ):
            raise PrincipalBindingError(
                "principal binding identity mismatch"
            )
        self._verify_binding_session(
            binding,
            now=self.readiness._now(),
        )
        return binding
