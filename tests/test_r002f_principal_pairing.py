from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hms_gpt_vps.agent_connection_registry import AgentPresence
from hms_gpt_vps.control_session_store import ControlSessionStore
from hms_gpt_vps.pairing_exchange import (
    PairingExchangeKey,
    PairingSessionExchange,
)
from hms_gpt_vps.pairing_link_lease import (
    PairingLinkLeaseStore,
)
from hms_gpt_vps.pairing_readiness_runtime import (
    PairingReadinessConfig,
    PairingReadinessRuntime,
)
from hms_gpt_vps.pairing_store import PairingStore
from hms_gpt_vps.principal_pairing_service import (
    PrincipalBindingError,
    PrincipalPairingConflictError,
    PrincipalPairingRejectedError,
    PrincipalPairingUnavailableError,
    PrincipalSessionBinding,
    PrincipalSessionBindingStore,
    PrincipalPairingService,
    TrustedIntegrationPrincipal,
    derive_principal_client_nonce,
)
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore


NOW = datetime(2026, 8, 25, 5, 45, tzinfo=timezone.utc)
INSTANCE_ID = "hms-01"
BRIDGE_BASE_URL = "https://bridge.example"


class MemorySecretStore:
    def __init__(self) -> None:
        self.value: str | None = None

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("secret missing")
        return self.value


class MemoryBindingRegistry:
    def __init__(self) -> None:
        self._stores: dict[tuple[str, str], PrincipalSessionBindingStore] = {}

    def store_for(
        self,
        principal_sha256: str,
        instance_id: str,
    ) -> PrincipalSessionBindingStore:
        key = (principal_sha256, instance_id)
        if key not in self._stores:
            self._stores[key] = PrincipalSessionBindingStore(
                MemorySecretStore()
            )
        return self._stores[key]


class PresenceReader:
    def __init__(self, presence: AgentPresence | None) -> None:
        self.presence = presence

    def get_presence(self, instance_id: str) -> AgentPresence | None:
        return self.presence


class Clock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def presence(at: datetime = NOW) -> AgentPresence:
    return AgentPresence(
        instance_id=INSTANCE_ID,
        device_id="device-01",
        boot_id="boot-01",
        connection_epoch=3,
        first_seen_at=at - timedelta(minutes=1),
        last_seen_at=at,
    )


def principal(subject: str = "user-01") -> TrustedIntegrationPrincipal:
    return TrustedIntegrationPrincipal(
        namespace="openai-app",
        subject=subject,
    )


def build_service(tmp_path: Path):
    db_path = tmp_path / "auth.sqlite3"
    pairing_store = PairingStore(db_path)
    session_store = ControlSessionStore(db_path)
    exchange = PairingSessionExchange(
        pairing_store,
        session_store,
        PairingExchangeKey(b"K" * 32),
    )

    provision = ProvisionStateStore(tmp_path / "provision.json")
    provision.transition(
        instance_id=INSTANCE_ID,
        state=ProvisionState.INSTALL_SECRETS_CLEARED,
    )
    clock = Clock()
    presence_reader = PresenceReader(presence())
    lease_secret = MemorySecretStore()
    readiness = PairingReadinessRuntime(
        PairingReadinessConfig(
            instance_id=INSTANCE_ID,
            bridge_base_url=BRIDGE_BASE_URL,
        ),
        provision,
        presence_reader,
        pairing_store,
        PairingLinkLeaseStore(lease_secret),
        tmp_path / "pairing-issuance.lock",
        clock=clock,
    )
    issued = readiness.issue()
    registry = MemoryBindingRegistry()
    service = PrincipalPairingService(
        readiness,
        exchange,
        registry,
        tmp_path / "principal-pairing.lock",
    )
    return (
        service,
        readiness,
        exchange,
        registry,
        pairing_store,
        session_store,
        clock,
        presence_reader,
        issued,
    )


def test_same_principal_pairing_is_idempotent_without_returning_session_token(
    tmp_path: Path,
) -> None:
    (
        service,
        _readiness,
        _exchange,
        registry,
        _pairing_store,
        _session_store,
        _clock,
        _presence_reader,
        issued,
    ) = build_service(tmp_path)
    who = principal()

    first = service.pair(who, issued.pairing_link)
    second = service.pair(who, issued.pairing_link)

    assert second == first
    assert first.instance_id == INSTANCE_ID
    assert first.session_id
    assert "session_token" not in repr(first)
    assert "session_token" not in first.__dict__

    store = registry.store_for(who.sha256(), INSTANCE_ID)
    binding = store.load()
    assert binding is not None
    assert binding.session_id == first.session_id
    assert binding.session_token not in repr(binding)


def test_wrong_pairing_link_is_rejected_before_pairing_consumption(
    tmp_path: Path,
) -> None:
    (
        service,
        _readiness,
        _exchange,
        _registry,
        pairing_store,
        _session_store,
        _clock,
        _presence_reader,
        issued,
    ) = build_service(tmp_path)

    with pytest.raises(PrincipalPairingRejectedError, match="does not match"):
        service.pair(principal(), issued.pairing_link + "x")

    current = pairing_store.require(issued.pair_id)
    assert current.consumed_at is None


def test_different_principal_cannot_claim_consumed_pairing(
    tmp_path: Path,
) -> None:
    (
        service,
        _readiness,
        _exchange,
        _registry,
        _pairing_store,
        _session_store,
        _clock,
        _presence_reader,
        issued,
    ) = build_service(tmp_path)

    first = service.pair(principal("user-01"), issued.pairing_link)
    assert first.session_id

    with pytest.raises(
        PrincipalPairingConflictError,
        match="different exchange authority",
    ):
        service.pair(principal("user-02"), issued.pairing_link)


def test_crash_after_exchange_before_binding_save_recovers_beyond_public_window(
    tmp_path: Path,
) -> None:
    (
        service,
        readiness,
        exchange,
        registry,
        _pairing_store,
        _session_store,
        clock,
        presence_reader,
        issued,
    ) = build_service(tmp_path)
    who = principal()
    lease = readiness.lease_store.load()
    assert lease is not None
    nonce = derive_principal_client_nonce(
        exchange.key,
        who.sha256(),
        issued.pair_id,
    )

    committed = exchange.exchange(
        issued.pair_id,
        lease.token,
        nonce,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )
    store = registry.store_for(who.sha256(), INSTANCE_ID)
    assert store.load() is None

    clock.value = NOW + timedelta(seconds=121)
    presence_reader.presence = presence(clock.value)
    recovered = service.pair(who, issued.pairing_link)

    assert recovered.session_id == committed.record.session_id
    binding = store.load()
    assert binding is not None
    assert binding.session_id == committed.record.session_id
    assert binding.session_token == committed.token


def test_load_active_binding_requires_exact_same_principal(tmp_path: Path) -> None:
    (
        service,
        _readiness,
        _exchange,
        _registry,
        _pairing_store,
        _session_store,
        _clock,
        _presence_reader,
        issued,
    ) = build_service(tmp_path)
    owner = principal("owner")
    service.pair(owner, issued.pairing_link)

    binding = service.load_active_binding(owner, INSTANCE_ID)
    assert binding.instance_id == INSTANCE_ID

    with pytest.raises(
        PrincipalPairingUnavailableError,
        match="no bound control session",
    ):
        service.load_active_binding(principal("other"), INSTANCE_ID)


def test_principal_subject_is_excluded_from_repr() -> None:
    who = principal("sensitive-subject-identifier")
    assert "sensitive-subject-identifier" not in repr(who)
    assert who.sha256() not in repr(who)


def test_binding_json_rejects_duplicate_keys() -> None:
    raw = (
        '{"schema_version":1,"schema_version":1,'
        '"principal_sha256":"' + ("a" * 64) + '",'
        '"instance_id":"hms-01",'
        '"pair_id":"pair-01",'
        '"session_id":"session-01",'
        '"family_id":"family-01",'
        '"session_token_sha256":"' + ("b" * 64) + '",'
        '"scopes":["workspace.read"],'
        '"issued_at":"2026-08-25T05:45:00Z",'
        '"expires_at":"2026-08-25T06:45:00Z",'
        '"epoch":1,"session_token":"secret"}'
    )
    with pytest.raises(PrincipalBindingError, match="duplicate JSON key"):
        PrincipalSessionBinding.from_json(raw)
