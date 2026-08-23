from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from hms_gpt_vps.agent_connection_epoch_store import (
    AgentConnectionEpochError,
    AgentConnectionEpochStore,
)
from hms_gpt_vps.agent_transport_codec import (
    parse_agent_command,
    parse_agent_command_result,
    parse_signed_agent_command,
)
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
    AgentCommandResult,
    AgentDeviceCredential,
    AgentTransportError,
    sign_bridge_command,
    verify_bridge_command,
)


def credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id="hms-01",
        device_id="device-01",
        secret=b"S" * 32,
    )


def command() -> AgentCommandEnvelope:
    return AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        action="workspace.read",
        params={"path": "hello.txt"},
        deadline_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


def test_signed_command_codec_round_trips_exact_protocol_objects() -> None:
    signed = sign_bridge_command(credential(), command())
    parsed = parse_signed_agent_command(signed.to_dict())

    assert parsed.command.request_id == "req-01"
    assert parsed.command.params == {"path": "hello.txt"}
    assert parsed.signature == signed.signature
    assert verify_bridge_command(credential(), parsed).request_id == "req-01"


def test_command_codec_rejects_missing_unknown_and_naive_time() -> None:
    payload = command().to_dict()
    payload["extra"] = True
    with pytest.raises(AgentTransportError, match="fields do not match schema"):
        parse_agent_command(payload)

    missing = command().to_dict()
    del missing["action"]
    with pytest.raises(AgentTransportError, match="missing=action"):
        parse_agent_command(missing)

    naive = command().to_dict()
    naive["deadline_at"] = "2026-08-23T12:00:00"
    with pytest.raises(AgentTransportError, match="timezone-aware"):
        parse_agent_command(naive)


def test_result_codec_round_trips_and_rejects_unknown_fields() -> None:
    result = AgentCommandResult(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        outcome="ok",
        response={"sha256": "a" * 64},
        completed_at=datetime.now(timezone.utc),
    )
    parsed = parse_agent_command_result(result.to_dict())
    assert parsed.request_id == result.request_id
    assert parsed.response == result.response

    payload = result.to_dict()
    payload["debug"] = "not allowed"
    with pytest.raises(AgentTransportError, match="fields do not match schema"):
        parse_agent_command_result(payload)


def test_connection_epoch_store_allocates_monotonically(tmp_path) -> None:
    store = AgentConnectionEpochStore(tmp_path / "epoch.sqlite3")
    first = store.allocate_next(instance_id="hms-01", device_id="device-01")
    second = store.allocate_next(instance_id="hms-01", device_id="device-01")
    third = store.allocate_next(instance_id="hms-01", device_id="device-01")

    assert [first.epoch, second.epoch, third.epoch] == [1, 2, 3]
    assert store.load() == third


def test_connection_epoch_store_concurrent_allocations_are_unique(tmp_path) -> None:
    path = tmp_path / "epoch.sqlite3"

    def allocate(_index: int) -> int:
        return AgentConnectionEpochStore(path).allocate_next(
            instance_id="hms-01",
            device_id="device-01",
        ).epoch

    with ThreadPoolExecutor(max_workers=8) as pool:
        epochs = list(pool.map(allocate, range(24)))

    assert sorted(epochs) == list(range(1, 25))
    assert AgentConnectionEpochStore(path).load().epoch == 24  # type: ignore[union-attr]


def test_connection_epoch_store_rejects_wrong_identity_without_mutating(tmp_path) -> None:
    store = AgentConnectionEpochStore(tmp_path / "epoch.sqlite3")
    first = store.allocate_next(instance_id="hms-01", device_id="device-01")

    with pytest.raises(AgentConnectionEpochError, match="another instance"):
        store.allocate_next(instance_id="hms-02", device_id="device-01")
    with pytest.raises(AgentConnectionEpochError, match="another device"):
        store.allocate_next(instance_id="hms-01", device_id="device-02")

    assert store.load() == first
