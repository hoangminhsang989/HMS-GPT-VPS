from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from .agent_connection_registry import AgentPresence
from .authority_lock import exclusive_authority_lock
from .pairing import (
    DEFAULT_PAIR_TTL_SECONDS,
    MAX_PAIR_TTL_SECONDS,
    PAIRABLE_SCOPES,
    PairingConsumedError,
    PairingGrant,
    PairingRecord,
    issue_pairing_grant,
)
from .pairing_link_lease import (
    PairingLinkLease,
    PairingLinkLeaseStore,
    normalize_pairing_bridge_base_url,
)
from .pairing_store import PairingStore
from .provision_state import ProvisionState, ProvisionStateStore
from .provisioning import ProvisionObservation


DEFAULT_PAIRING_PRESENCE_MAX_AGE_SECONDS = 90
MAX_PAIRING_PRESENCE_MAX_AGE_SECONDS = 900


class PairingReadinessError(RuntimeError):
    pass


class PairingPresenceUnavailableError(PairingReadinessError):
    pass


class PairingPresenceStaleError(PairingReadinessError):
    pass


class PairingStateError(PairingReadinessError):
    pass


class PresenceReader(Protocol):
    def get_presence(self, instance_id: str) -> AgentPresence | None: ...


@dataclass(frozen=True)
class PairingReadinessConfig:
    instance_id: str
    bridge_base_url: str
    presence_max_age_seconds: int = DEFAULT_PAIRING_PRESENCE_MAX_AGE_SECONDS
    pair_ttl_seconds: int = DEFAULT_PAIR_TTL_SECONDS
    scopes: tuple[str, ...] = field(default_factory=lambda: tuple(sorted(PAIRABLE_SCOPES)))

    def validate(self) -> None:
        if not isinstance(self.instance_id, str) or not self.instance_id.strip():
            raise ValueError("instance_id is required")
        if not isinstance(self.bridge_base_url, str) or not self.bridge_base_url:
            raise ValueError("bridge_base_url is required")
        try:
            normalized_bridge = normalize_pairing_bridge_base_url(self.bridge_base_url)
        except RuntimeError as exc:
            raise ValueError("bridge_base_url is invalid") from exc
        if normalized_bridge != self.bridge_base_url:
            raise ValueError("bridge_base_url must use canonical form")
        if (
            isinstance(self.presence_max_age_seconds, bool)
            or not isinstance(self.presence_max_age_seconds, int)
            or not 1 <= self.presence_max_age_seconds <= MAX_PAIRING_PRESENCE_MAX_AGE_SECONDS
        ):
            raise ValueError("presence_max_age_seconds must be an integer between 1 and 900")
        if (
            isinstance(self.pair_ttl_seconds, bool)
            or not isinstance(self.pair_ttl_seconds, int)
            or not 60 <= self.pair_ttl_seconds <= MAX_PAIR_TTL_SECONDS
        ):
            raise ValueError("pair_ttl_seconds must be an integer between 60 and 1800")
        if not isinstance(self.scopes, tuple) or not self.scopes:
            raise ValueError("pairing scopes must be a non-empty tuple")
        if any(not isinstance(scope, str) or scope not in PAIRABLE_SCOPES for scope in self.scopes):
            raise ValueError("pairing scopes contain an unsupported value")
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("pairing scopes must be unique")


@dataclass(frozen=True)
class PairingReadinessObservation:
    pairing_ready: bool
    paired: bool
    pair_id: str | None = None
    expires_at: datetime | None = None

    def to_provision_observation(self) -> ProvisionObservation:
        return ProvisionObservation(
            pairing_ready=self.pairing_ready,
            paired=self.paired,
        )


@dataclass(frozen=True)
class PairingIssueResult:
    pair_id: str
    expires_at: datetime
    pairing_link: str = field(repr=False)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PairingReadinessError("pairing runtime clock must be timezone-aware")
    return value.astimezone(timezone.utc)


class PairingReadinessRuntime:
    """Crash-recoverable bridge-side gate for issuing one one-time pairing URL.

    This runtime never advances provisioning state. It only mutates pairing
    authority under its own lock and returns observations that the existing
    provisioning orchestrator may later consume.
    """

    def __init__(
        self,
        config: PairingReadinessConfig,
        provision_store: ProvisionStateStore,
        presence_reader: PresenceReader,
        pairing_store: PairingStore,
        lease_store: PairingLinkLeaseStore,
        lock_path: Path,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        config.validate()
        self.config = config
        self.provision_store = provision_store
        self.presence_reader = presence_reader
        self.pairing_store = pairing_store
        self.lease_store = lease_store
        self.lock_path = lock_path.expanduser().absolute()
        self.clock = clock

    def _now(self) -> datetime:
        return _aware_utc(self.clock())

    def _require_pairing_state(self) -> ProvisionState:
        record = self.provision_store.load()
        if record is None:
            raise PairingStateError("provision state does not exist")
        if record.instance_id != self.config.instance_id:
            raise PairingStateError("provision state belongs to another instance")
        if record.state not in {
            ProvisionState.INSTALL_SECRETS_CLEARED,
            ProvisionState.PAIRING_PENDING,
        }:
            raise PairingStateError(
                "pairing issuance requires INSTALL_SECRETS_CLEARED or PAIRING_PENDING"
            )
        return record.state

    def _presence(self, now: datetime) -> AgentPresence:
        presence = self.presence_reader.get_presence(self.config.instance_id)
        if presence is None:
            raise PairingPresenceUnavailableError("authenticated Agent presence is unavailable")
        if presence.instance_id != self.config.instance_id:
            raise PairingReadinessError("Agent presence belongs to another instance")
        if not isinstance(presence.device_id, str) or not presence.device_id:
            raise PairingReadinessError("Agent presence device_id is invalid")
        if not isinstance(presence.boot_id, str) or not presence.boot_id:
            raise PairingReadinessError("Agent presence boot_id is invalid")
        if (
            isinstance(presence.connection_epoch, bool)
            or not isinstance(presence.connection_epoch, int)
            or presence.connection_epoch < 1
        ):
            raise PairingReadinessError("Agent presence connection_epoch is invalid")
        first = _aware_utc(presence.first_seen_at)
        last = _aware_utc(presence.last_seen_at)
        if last < first:
            raise PairingReadinessError("Agent presence timestamps are inconsistent")
        age = (now - last).total_seconds()
        if age < 0:
            raise PairingReadinessError("Agent presence timestamp is in the future")
        if age > self.config.presence_max_age_seconds:
            raise PairingPresenceStaleError("authenticated Agent presence is stale")
        return presence

    @staticmethod
    def _same_initial_record(current: PairingRecord, initial: PairingRecord) -> bool:
        current.validate()
        initial.validate()
        return (
            current.schema_version == initial.schema_version
            and current.pair_id == initial.pair_id
            and current.instance_id == initial.instance_id
            and current.token_sha256 == initial.token_sha256
            and current.scopes == initial.scopes
            and current.issued_at == initial.issued_at
            and current.expires_at == initial.expires_at
        )

    def _require_lease_authority(self, lease: PairingLinkLease) -> None:
        lease.validate()
        if lease.record.instance_id != self.config.instance_id:
            raise PairingReadinessError("pairing lease belongs to another instance")
        if lease.bridge_base_url != self.config.bridge_base_url:
            raise PairingReadinessError("pairing lease Bridge origin differs from runtime authority")

    @staticmethod
    def _issue_result(lease: PairingLinkLease) -> PairingIssueResult:
        return PairingIssueResult(
            pair_id=lease.record.pair_id,
            expires_at=lease.record.expires_at,
            pairing_link=lease.pairing_link,
        )

    def _recover_or_return_existing(
        self,
        lease: PairingLinkLease,
        *,
        now: datetime,
    ) -> PairingIssueResult | None:
        self._require_lease_authority(lease)
        current = self.pairing_store.get(lease.record.pair_id)
        if current is None:
            if now < lease.record.issued_at:
                raise PairingReadinessError("pairing lease is not yet valid")
            if now >= lease.record.expires_at:
                return None
            self._require_pairing_state()
            self._presence(self._now())
            self.pairing_store.create(lease.record)
            current = self.pairing_store.require(lease.record.pair_id)

        if not self._same_initial_record(current, lease.record):
            raise PairingReadinessError("pairing store record differs from encrypted lease authority")
        if current.consumed_at is not None:
            raise PairingConsumedError("pairing grant is already consumed")
        if current.revoked_at is not None or now >= current.expires_at:
            return None
        if now < current.issued_at:
            raise PairingReadinessError("pairing grant is not yet valid")
        return self._issue_result(lease)

    def issue(self) -> PairingIssueResult:
        with exclusive_authority_lock(self.lock_path):
            self._require_pairing_state()
            now = self._now()
            self._presence(now)

            existing = self.lease_store.load()
            if existing is not None:
                recovered = self._recover_or_return_existing(existing, now=now)
                if recovered is not None:
                    return recovered

            grant: PairingGrant = issue_pairing_grant(
                self.config.instance_id,
                self.config.bridge_base_url,
                scopes=self.config.scopes,
                now=now,
                ttl_seconds=self.config.pair_ttl_seconds,
            )
            lease = PairingLinkLease.from_grant(grant, self.config.bridge_base_url)

            # Crash-safe ordering is deliberate: persist the recoverable raw
            # token/link before publishing the digest-only pairing record.
            self.lease_store.save(lease)

            self._require_pairing_state()
            self._presence(self._now())
            self.pairing_store.create(grant.record)
            readback = self.pairing_store.require(grant.record.pair_id)
            if not self._same_initial_record(readback, grant.record):
                raise PairingReadinessError("pairing record readback differs from issued authority")
            return self._issue_result(lease)

    def observe(self) -> PairingReadinessObservation:
        state = self.provision_store.load()
        if state is None or state.instance_id != self.config.instance_id:
            return PairingReadinessObservation(False, False)
        if state.state not in {
            ProvisionState.INSTALL_SECRETS_CLEARED,
            ProvisionState.PAIRING_PENDING,
            ProvisionState.READY,
        }:
            return PairingReadinessObservation(False, False)

        now = self._now()
        try:
            self._presence(now)
        except (PairingPresenceUnavailableError, PairingPresenceStaleError):
            return PairingReadinessObservation(False, False)

        lease = self.lease_store.load()
        if lease is None:
            return PairingReadinessObservation(False, False)
        self._require_lease_authority(lease)
        current = self.pairing_store.get(lease.record.pair_id)
        if current is None:
            return PairingReadinessObservation(False, False)
        if not self._same_initial_record(current, lease.record):
            raise PairingReadinessError("pairing store record differs from encrypted lease authority")
        if current.consumed_at is not None:
            return PairingReadinessObservation(
                True,
                True,
                pair_id=current.pair_id,
                expires_at=current.expires_at,
            )
        if current.revoked_at is not None or now < current.issued_at or now >= current.expires_at:
            return PairingReadinessObservation(False, False)
        return PairingReadinessObservation(
            True,
            False,
            pair_id=current.pair_id,
            expires_at=current.expires_at,
        )

    def current_pairing_link(self) -> str:
        self._require_pairing_state()
        now = self._now()
        self._presence(now)
        lease = self.lease_store.load()
        if lease is None:
            raise PairingReadinessError("pairing link lease does not exist")
        self._require_lease_authority(lease)
        current = self.pairing_store.require(lease.record.pair_id)
        if not self._same_initial_record(current, lease.record):
            raise PairingReadinessError("pairing store record differs from encrypted lease authority")
        if current.consumed_at is not None:
            raise PairingConsumedError("pairing grant is already consumed")
        if current.revoked_at is not None or now < current.issued_at or now >= current.expires_at:
            raise PairingReadinessError("pairing link is not active")
        return lease.pairing_link
