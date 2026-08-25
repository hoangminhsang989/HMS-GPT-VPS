from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

import pytest

from hms_gpt_vps.agent_connection_registry import (
    AgentConnectionRegistry,
    AgentConnectionRegistryError,
)
from hms_gpt_vps.agent_transport_protocol import VerifiedAgentRequest
from hms_gpt_vps.pairing import (
    PairingError,
    PairingRecord,
    issue_pairing_grant,
)
from hms_gpt_vps.pairing_store import PairingStore, PairingStoreError


NOW = datetime(2026, 8, 25, 5, 0, tzinfo=timezone.utc)


def verified_request(*, epoch: int = 1, nonce: str = "nonce-01") -> VerifiedAgentRequest:
    return VerifiedAgentRequest(
        device_id="device-01",
        instance_id="hms-01",
        boot_id="boot-01",
        connection_epoch=epoch,
        timestamp=NOW,
        nonce=nonce,
        body_sha256="0" * 64,
    )


@pytest.mark.parametrize("bad_schema", [True, "1", 1.0, None])
def test_pairing_record_from_dict_rejects_schema_coercion(bad_schema: object) -> None:
    grant = issue_pairing_grant("hms-01", "https://bridge.example", now=NOW)
    payload = grant.record.to_dict()
    payload["schema_version"] = bad_schema
    with pytest.raises(PairingError, match="schema_version"):
        PairingRecord.from_dict(payload)


def test_pairing_record_rejects_unknown_fields_uppercase_digest_and_bool_ttl() -> None:
    grant = issue_pairing_grant("hms-01", "https://bridge.example", now=NOW)
    extra = grant.record.to_dict()
    extra["extra"] = True
    with pytest.raises(PairingError, match="fields"):
        PairingRecord.from_dict(extra)

    upper = grant.record.to_dict()
    upper["token_sha256"] = grant.record.token_sha256.upper()
    with pytest.raises(PairingError, match="canonical lowercase"):
        PairingRecord.from_dict(upper)

    with pytest.raises(PairingError, match="integer"):
        issue_pairing_grant(
            "hms-01",
            "https://bridge.example",
            now=NOW,
            ttl_seconds=True,  # type: ignore[arg-type]
        )


def test_pairing_store_normal_roundtrip_and_consume(tmp_path: Path) -> None:
    store = PairingStore(tmp_path / "pairing.sqlite3")
    grant = issue_pairing_grant("hms-01", "https://bridge.example", now=NOW)
    store.create(grant.record)
    loaded = store.require(grant.record.pair_id)
    assert loaded == grant.record

    consumed = store.consume(
        grant.record.pair_id,
        grant.token,
        instance_id="hms-01",
        now=NOW,
    )
    assert consumed.consumed_at == NOW


def test_pairing_store_rejects_tampered_stored_json_types(tmp_path: Path) -> None:
    store = PairingStore(tmp_path / "pairing.sqlite3")
    grant = issue_pairing_grant("hms-01", "https://bridge.example", now=NOW)
    store.create(grant.record)

    payload = grant.record.to_dict()
    payload["schema_version"] = "1"
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE pairing_records SET record_json = ? WHERE pair_id = ?",
            (raw, grant.record.pair_id),
        )

    with pytest.raises(PairingStoreError, match="validation"):
        store.require(grant.record.pair_id)


def test_pairing_store_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    store = PairingStore(tmp_path / "pairing.sqlite3")
    grant = issue_pairing_grant("hms-01", "https://bridge.example", now=NOW)
    store.create(grant.record)
    raw = store._serialize(grant.record)
    duplicate = raw[:-1] + ',"schema_version":1}'
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE pairing_records SET record_json = ? WHERE pair_id = ?",
            (duplicate, grant.record.pair_id),
        )
    with pytest.raises(PairingStoreError, match="duplicate"):
        store.require(grant.record.pair_id)


@pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), 31])
def test_sqlite_authority_rejects_invalid_timeouts(tmp_path: Path, timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        PairingStore(
            tmp_path / "pairing.sqlite3",
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="timeout_seconds"):
        AgentConnectionRegistry(
            tmp_path / "agent.sqlite3",
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


def test_pairing_and_presence_stores_reject_symlinked_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    redirected = tmp_path / "redirected"
    try:
        redirected.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")

    with pytest.raises((PairingStoreError, ValueError), match="link|reparse"):
        PairingStore(redirected / "pairing.sqlite3")
    with pytest.raises((AgentConnectionRegistryError, ValueError), match="link|reparse"):
        AgentConnectionRegistry(redirected / "agent.sqlite3")


def test_agent_connection_registry_roundtrip_uses_exact_presence_types(tmp_path: Path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "agent.sqlite3")
    accepted = registry.accept_verified_request(verified_request(), now=NOW)
    assert accepted.instance_id == "hms-01"
    assert accepted.device_id == "device-01"
    assert accepted.connection_epoch == 1
    assert accepted.last_seen_at == NOW

    loaded = registry.get_presence("hms-01")
    assert loaded == accepted


def test_agent_connection_registry_rejects_tampered_epoch_type(tmp_path: Path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "agent.sqlite3")
    registry.accept_verified_request(verified_request(), now=NOW)

    with sqlite3.connect(registry.path) as connection:
        connection.execute(
            "UPDATE agent_presence SET connection_epoch = ? WHERE instance_id = ?",
            ("4x", "hms-01"),
        )

    with pytest.raises(AgentConnectionRegistryError, match="connection_epoch"):
        registry.get_presence("hms-01")


def test_agent_connection_registry_rejects_tampered_timestamp_type(tmp_path: Path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "agent.sqlite3")
    registry.accept_verified_request(verified_request(), now=NOW)

    with sqlite3.connect(registry.path) as connection:
        connection.execute(
            "UPDATE agent_presence SET last_seen_unix = ? WHERE instance_id = ?",
            ("not-a-number", "hms-01"),
        )

    with pytest.raises(AgentConnectionRegistryError, match="last_seen_unix"):
        registry.get_presence("hms-01")


def test_database_path_replacement_is_rejected_between_operations(tmp_path: Path) -> None:
    store = PairingStore(tmp_path / "pairing.sqlite3")
    grant = issue_pairing_grant("hms-01", "https://bridge.example", now=NOW)
    store.create(grant.record)

    original = store.path
    moved = tmp_path / "pairing-original.sqlite3"
    original.replace(moved)
    original.write_bytes(moved.read_bytes())

    with pytest.raises(PairingStoreError, match="startup authority"):
        store.require(grant.record.pair_id)


def test_agent_registry_path_replacement_is_rejected_between_operations(tmp_path: Path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "agent.sqlite3")
    registry.accept_verified_request(verified_request(), now=NOW)

    original = registry.path
    moved = tmp_path / "agent-original.sqlite3"
    original.replace(moved)
    original.write_bytes(moved.read_bytes())

    with pytest.raises(AgentConnectionRegistryError, match="startup authority"):
        registry.get_presence("hms-01")
