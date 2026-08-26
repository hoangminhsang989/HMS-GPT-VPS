from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hms_gpt_vps.agent_connection_registry import AgentPresence
from hms_gpt_vps.control_session_store import ControlSessionStore
from hms_gpt_vps.pairing_exchange import PairingExchangeKey, PairingSessionExchange
from hms_gpt_vps.pairing_link_lease import PairingLinkLeaseStore
from hms_gpt_vps.pairing_readiness_runtime import (
    PairingReadinessConfig,
    PairingReadinessRuntime,
)
from hms_gpt_vps.pairing_store import PairingStore
from hms_gpt_vps.principal_pairing_service import (
    PrincipalSessionBindingStore,
    TrustedIntegrationPrincipal,
)
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps.provision_state_bound_principal_pairing import (
    ProvisionStateBoundPrincipalPairingService,
)


NOW = datetime(2026, 8, 26, 1, 0, tzinfo=timezone.utc)
INSTANCE_ID = "hms-01"


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
        self.stores: dict[tuple[str, str], PrincipalSessionBindingStore] = {}

    def store_for(
        self,
        principal_sha256: str,
        instance_id: str,
    ) -> PrincipalSessionBindingStore:
        key = (principal_sha256, instance_id)
        if key not in self.stores:
            self.stores[key] = PrincipalSessionBindingStore(MemorySecretStore())
        return self.stores[key]


class PresenceReader:
    def __init__(self) -> None:
        self.value = AgentPresence(
            instance_id=INSTANCE_ID,
            device_id="device-01",
            boot_id="boot-01",
            connection_epoch=2,
            first_seen_at=NOW - timedelta(minutes=1),
            last_seen_at=NOW,
        )

    def get_presence(self, instance_id: str) -> AgentPresence | None:
        return self.value


class Clock:
    def __call__(self) -> datetime:
        return NOW


def build_service(tmp_path: Path):
    provision = ProvisionStateStore(tmp_path / "provision.json")
    provision.transition(
        instance_id=INSTANCE_ID,
        state=ProvisionState.INSTALL_SECRETS_CLEARED,
    )
    auth_db = tmp_path / "auth.sqlite3"
    pairing = PairingStore(auth_db)
    sessions = ControlSessionStore(auth_db)
    exchange = PairingSessionExchange(
        pairing,
        sessions,
        PairingExchangeKey(b"K" * 32),
    )
    readiness = PairingReadinessRuntime(
        PairingReadinessConfig(
            instance_id=INSTANCE_ID,
            bridge_base_url="https://bridge.example",
        ),
        provision,
        PresenceReader(),
        pairing,
        PairingLinkLeaseStore(MemorySecretStore()),
        tmp_path / "pairing.lock",
        clock=Clock(),
    )
    issued = readiness.issue()
    registry = MemoryBindingRegistry()
    service = ProvisionStateBoundPrincipalPairingService(
        readiness,
        exchange,
        registry,
        tmp_path / "principal.lock",
    )
    who = TrustedIntegrationPrincipal("openai-app", "real-principal")
    return service, readiness, provision, registry, issued, who


def test_durable_principal_binding_commits_ready(tmp_path: Path) -> None:
    service, _readiness, provision, registry, issued, who = build_service(tmp_path)
    pending = provision.load()
    assert pending is not None
    assert pending.state is ProvisionState.PAIRING_PENDING

    result = service.pair(who, issued.pairing_link)

    binding = registry.store_for(who.sha256(), INSTANCE_ID).load()
    assert binding is not None
    assert binding.session_id == result.session_id
    ready = provision.load()
    assert ready is not None
    assert ready.state is ProvisionState.READY
    assert ready.reason == "principal_binding_published"


def test_crash_after_binding_before_ready_recovers_idempotently(
    tmp_path: Path,
) -> None:
    service, readiness, provision, registry, issued, who = build_service(tmp_path)
    original_commit = readiness.commit_principal_binding_ready

    def crash_after_binding() -> None:
        raise RuntimeError("synthetic crash after durable binding")

    readiness.commit_principal_binding_ready = crash_after_binding  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="synthetic crash"):
        service.pair(who, issued.pairing_link)

    binding = registry.store_for(who.sha256(), INSTANCE_ID).load()
    assert binding is not None
    pending = provision.load()
    assert pending is not None
    assert pending.state is ProvisionState.PAIRING_PENDING

    readiness.commit_principal_binding_ready = original_commit  # type: ignore[method-assign]
    recovered = service.pair(who, issued.pairing_link)
    assert recovered.session_id == binding.session_id
    ready = provision.load()
    assert ready is not None
    assert ready.state is ProvisionState.READY


def test_failed_pair_does_not_advance_ready(tmp_path: Path) -> None:
    service, _readiness, provision, _registry, issued, who = build_service(tmp_path)
    with pytest.raises(Exception):
        service.pair(who, issued.pairing_link + "x")
    checkpoint = provision.load()
    assert checkpoint is not None
    assert checkpoint.state is ProvisionState.PAIRING_PENDING
