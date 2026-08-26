from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hms_gpt_vps.agent_connection_registry import AgentPresence
from hms_gpt_vps.pairing import PairingConsumedError, issue_pairing_grant
from hms_gpt_vps.pairing_link_lease import PairingLinkLease, PairingLinkLeaseStore
from hms_gpt_vps.pairing_readiness_runtime import (
    PairingPresenceStaleError,
    PairingReadinessConfig,
    PairingReadinessRuntime,
    PairingStateError,
)
from hms_gpt_vps.pairing_store import PairingStore
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore


NOW = datetime(2026, 8, 25, 4, 30, tzinfo=timezone.utc)


class MemorySecretStore:
    def __init__(self) -> None:
        self.value: str | None = None

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("pairing lease missing")
        return self.value

    def clear(self) -> None:
        self.value = None


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
        instance_id="hms-01",
        device_id="device-01",
        boot_id="boot-01",
        connection_epoch=4,
        first_seen_at=at - timedelta(minutes=2),
        last_seen_at=at,
    )


def build_runtime(
    tmp_path: Path,
    *,
    clock: Clock | None = None,
    current_presence: AgentPresence | None = None,
) -> tuple[
    PairingReadinessRuntime,
    ProvisionStateStore,
    PairingStore,
    PairingLinkLeaseStore,
    MemorySecretStore,
]:
    provision = ProvisionStateStore(tmp_path / "provision.json")
    provision.transition(
        instance_id="hms-01",
        state=ProvisionState.INSTALL_SECRETS_CLEARED,
    )
    pairing = PairingStore(tmp_path / "pairing.sqlite3")
    secret = MemorySecretStore()
    lease = PairingLinkLeaseStore(secret)
    runtime = PairingReadinessRuntime(
        PairingReadinessConfig(
            instance_id="hms-01",
            bridge_base_url="https://bridge.example",
        ),
        provision,
        PresenceReader(current_presence if current_presence is not None else presence()),
        pairing,
        lease,
        tmp_path / "pairing-issuance.lock",
        clock=clock or Clock(),
    )
    return runtime, provision, pairing, lease, secret


def test_issue_is_recoverable_and_commits_pairing_pending(tmp_path: Path) -> None:
    runtime, provision, pairing, lease_store, _secret = build_runtime(tmp_path)

    first = runtime.issue()
    second = runtime.issue()
    assert second.pair_id == first.pair_id
    assert second.pairing_link == first.pairing_link

    record = provision.load()
    assert record is not None
    assert record.state is ProvisionState.PAIRING_PENDING
    assert record.reason == "pairing_authority_published"

    stored = pairing.require(first.pair_id)
    lease = lease_store.load()
    assert lease is not None
    assert stored.token_sha256 == lease.record.token_sha256
    assert lease.token not in repr(lease)
    assert lease.pairing_link not in repr(lease)
    assert first.pairing_link not in repr(first)


def test_restart_recovers_same_copyable_link(tmp_path: Path) -> None:
    runtime, provision, pairing, _lease_store, secret = build_runtime(tmp_path)
    first = runtime.issue()

    restarted = PairingReadinessRuntime(
        runtime.config,
        provision,
        PresenceReader(presence()),
        pairing,
        PairingLinkLeaseStore(secret),
        tmp_path / "pairing-issuance.lock",
        clock=Clock(),
    )
    assert restarted.current_pairing_link() == first.pairing_link
    assert restarted.issue().pairing_link == first.pairing_link


def test_crash_after_encrypted_lease_before_digest_record_recovers_exact_grant(
    tmp_path: Path,
) -> None:
    runtime, provision, pairing, lease_store, _secret = build_runtime(tmp_path)
    grant = issue_pairing_grant(
        "hms-01",
        "https://bridge.example",
        now=NOW,
        ttl_seconds=600,
    )
    lease_store.save(PairingLinkLease.from_grant(grant, "https://bridge.example"))
    assert pairing.get(grant.record.pair_id) is None

    recovered = runtime.issue()
    assert recovered.pair_id == grant.record.pair_id
    assert recovered.pairing_link == grant.pairing_link
    stored = pairing.require(grant.record.pair_id)
    assert stored.token_sha256 == grant.record.token_sha256
    checkpoint = provision.load()
    assert checkpoint is not None
    assert checkpoint.state is ProvisionState.PAIRING_PENDING


def test_current_link_recovers_state_commit_after_pair_record_publication(
    tmp_path: Path,
) -> None:
    runtime, provision, pairing, lease_store, _secret = build_runtime(tmp_path)
    grant = issue_pairing_grant(
        "hms-01",
        "https://bridge.example",
        now=NOW,
        ttl_seconds=600,
    )
    lease_store.save(PairingLinkLease.from_grant(grant, "https://bridge.example"))
    pairing.create(grant.record)
    before = provision.load()
    assert before is not None
    assert before.state is ProvisionState.INSTALL_SECRETS_CLEARED

    assert runtime.current_pairing_link() == grant.pairing_link
    after = provision.load()
    assert after is not None
    assert after.state is ProvisionState.PAIRING_PENDING


def test_stale_or_missing_authenticated_presence_blocks_issuance(tmp_path: Path) -> None:
    stale = presence(NOW - timedelta(seconds=91))
    runtime, provision, pairing, lease_store, _secret = build_runtime(
        tmp_path,
        current_presence=stale,
    )
    with pytest.raises(PairingPresenceStaleError):
        runtime.issue()
    assert lease_store.load() is None

    missing_runtime = PairingReadinessRuntime(
        runtime.config,
        provision,
        PresenceReader(None),
        pairing,
        lease_store,
        tmp_path / "pairing-issuance.lock",
        clock=Clock(),
    )
    assert missing_runtime.observe().pairing_ready is False
    assert missing_runtime.observe().paired is False


def test_consumed_grant_observes_pairing_ready_and_paired_without_replacement(
    tmp_path: Path,
) -> None:
    clock = Clock()
    runtime, _provision, pairing, lease_store, _secret = build_runtime(
        tmp_path,
        clock=clock,
    )
    issued = runtime.issue()
    lease = lease_store.load()
    assert lease is not None

    clock.value = NOW + timedelta(seconds=5)
    pairing.consume(
        issued.pair_id,
        lease.token,
        instance_id="hms-01",
        now=clock.value,
    )
    observed = runtime.observe()
    assert observed.pairing_ready is True
    assert observed.paired is True
    assert observed.pair_id == issued.pair_id

    with pytest.raises(PairingConsumedError):
        runtime.issue()


def test_ready_commit_rejects_unconsumed_pairing(tmp_path: Path) -> None:
    runtime, provision, _pairing, _lease_store, _secret = build_runtime(tmp_path)
    runtime.issue()

    with pytest.raises(PairingStateError, match="consumed pairing authority"):
        runtime.commit_principal_binding_ready()

    checkpoint = provision.load()
    assert checkpoint is not None
    assert checkpoint.state is ProvisionState.PAIRING_PENDING


def test_expired_unconsumed_grant_is_replaced_only_with_fresh_presence(tmp_path: Path) -> None:
    clock = Clock()
    runtime, _provision, pairing, lease_store, _secret = build_runtime(
        tmp_path,
        clock=clock,
    )
    first = runtime.issue()
    clock.value = NOW + timedelta(seconds=601)
    runtime.presence_reader = PresenceReader(presence(clock.value))

    assert runtime.observe().pairing_ready is False
    second = runtime.issue()
    assert second.pair_id != first.pair_id
    assert second.pairing_link != first.pairing_link
    lease = lease_store.load()
    assert lease is not None
    assert lease.record.pair_id == second.pair_id
    assert pairing.require(first.pair_id).consumed_at is None


def test_runtime_observation_maps_to_existing_provisioning_contract(tmp_path: Path) -> None:
    runtime, _provision, _pairing, _lease, _secret = build_runtime(tmp_path)
    runtime.issue()
    observed = runtime.observe()
    provision_observation = observed.to_provision_observation()
    assert provision_observation.pairing_ready is True
    assert provision_observation.paired is False


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("presence_max_age_seconds", True),
        ("presence_max_age_seconds", 0),
        ("presence_max_age_seconds", 901),
        ("pair_ttl_seconds", True),
        ("pair_ttl_seconds", 59),
        ("pair_ttl_seconds", 1801),
    ],
)
def test_config_rejects_non_exact_or_out_of_bound_numeric_authority(
    field_name: str,
    value: object,
) -> None:
    config = PairingReadinessConfig(
        instance_id="hms-01",
        bridge_base_url="https://bridge.example",
    )
    with pytest.raises(ValueError):
        replace(config, **{field_name: value}).validate()


def test_lease_parser_rejects_truthy_schema_and_plaintext_is_repr_hidden() -> None:
    grant = issue_pairing_grant(
        "hms-01",
        "https://bridge.example",
        now=NOW,
    )
    lease = PairingLinkLease.from_grant(grant, "https://bridge.example")
    text = lease.to_json()
    assert grant.token in text
    assert grant.token not in repr(lease)
    tampered = text.replace('"schema_version":1', '"schema_version":true', 1)
    with pytest.raises(Exception):
        PairingLinkLease.from_json(tampered)


def test_pairing_issue_requires_post_secret_cleanup_state(tmp_path: Path) -> None:
    runtime, provision, _pairing, _lease, _secret = build_runtime(tmp_path)
    provision.transition(instance_id="hms-01", state=ProvisionState.AGENT_HEALTHY)
    with pytest.raises(Exception, match="INSTALL_SECRETS_CLEARED|PAIRING_PENDING"):
        runtime.issue()


def test_current_copy_link_is_hidden_outside_pairing_states(tmp_path: Path) -> None:
    runtime, provision, _pairing, _lease, _secret = build_runtime(tmp_path)
    runtime.issue()
    provision.transition(instance_id="hms-01", state=ProvisionState.READY)
    with pytest.raises(Exception, match="INSTALL_SECRETS_CLEARED|PAIRING_PENDING"):
        runtime.current_pairing_link()
