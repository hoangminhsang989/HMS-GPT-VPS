from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from hms_gpt_vps.agent_connection_registry import (
    AgentBootConflictError,
    AgentConnectionRegistry,
    AgentDeviceConflictError,
    AgentRequestReplayError,
    AgentStaleConnectionError,
)
from hms_gpt_vps.agent_transport_protocol import VerifiedAgentRequest


NOW = datetime(2026, 8, 23, 11, 0, tzinfo=timezone.utc)


def verified(
    *,
    device_id: str = "device-01",
    instance_id: str = "hms-01",
    boot_id: str = "boot-01",
    epoch: int = 1,
    nonce: str = "agent-nonce-0123456789",
) -> VerifiedAgentRequest:
    return VerifiedAgentRequest(
        device_id=device_id,
        instance_id=instance_id,
        boot_id=boot_id,
        connection_epoch=epoch,
        timestamp=NOW,
        nonce=nonce,
        body_sha256="a" * 64,
    )


def test_first_verified_request_establishes_presence(tmp_path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "presence.sqlite3")
    presence = registry.accept_verified_request(verified(), now=NOW)

    assert presence.instance_id == "hms-01"
    assert presence.device_id == "device-01"
    assert presence.boot_id == "boot-01"
    assert presence.connection_epoch == 1
    assert registry.get_presence("hms-01") == presence


def test_unique_nonce_same_epoch_same_boot_updates_heartbeat(tmp_path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "presence.sqlite3")
    first = registry.accept_verified_request(verified(), now=NOW)
    second = registry.accept_verified_request(
        verified(nonce="agent-nonce-ABCDEFGHIJ"),
        now=NOW + timedelta(seconds=5),
    )

    assert second.first_seen_at == first.first_seen_at
    assert second.last_seen_at > first.last_seen_at
    assert second.connection_epoch == 1


def test_duplicate_nonce_is_rejected(tmp_path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "presence.sqlite3")
    request = verified()
    registry.accept_verified_request(request, now=NOW)

    with pytest.raises(AgentRequestReplayError, match="already been used"):
        registry.accept_verified_request(request, now=NOW + timedelta(seconds=1))


def test_lower_epoch_is_stale(tmp_path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "presence.sqlite3")
    registry.accept_verified_request(verified(epoch=3), now=NOW)

    with pytest.raises(AgentStaleConnectionError, match="stale"):
        registry.accept_verified_request(
            verified(epoch=2, nonce="agent-nonce-epoch-two-01"),
            now=NOW + timedelta(seconds=1),
        )

    assert registry.get_presence("hms-01").connection_epoch == 3


def test_same_epoch_cannot_change_boot_identity(tmp_path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "presence.sqlite3")
    registry.accept_verified_request(verified(epoch=4), now=NOW)

    with pytest.raises(AgentBootConflictError, match="boot identity"):
        registry.accept_verified_request(
            verified(
                epoch=4,
                boot_id="boot-02",
                nonce="agent-nonce-new-boot-001",
            ),
            now=NOW + timedelta(seconds=1),
        )


def test_higher_epoch_supersedes_previous_boot(tmp_path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "presence.sqlite3")
    first = registry.accept_verified_request(verified(epoch=4), now=NOW)
    newer = registry.accept_verified_request(
        verified(
            epoch=5,
            boot_id="boot-02",
            nonce="agent-nonce-new-boot-001",
        ),
        now=NOW + timedelta(seconds=2),
    )

    assert newer.first_seen_at == first.first_seen_at
    assert newer.boot_id == "boot-02"
    assert newer.connection_epoch == 5


def test_instance_cannot_silently_switch_device(tmp_path) -> None:
    registry = AgentConnectionRegistry(tmp_path / "presence.sqlite3")
    registry.accept_verified_request(verified(), now=NOW)

    with pytest.raises(AgentDeviceConflictError, match="another Agent device"):
        registry.accept_verified_request(
            verified(
                device_id="device-02",
                epoch=2,
                nonce="agent-nonce-device-two01",
            ),
            now=NOW + timedelta(seconds=1),
        )


def test_concurrent_duplicate_nonce_has_exactly_one_winner(tmp_path) -> None:
    path = tmp_path / "presence.sqlite3"
    AgentConnectionRegistry(path)
    request = verified()

    def attempt(index: int) -> str:
        registry = AgentConnectionRegistry(path)
        try:
            registry.accept_verified_request(
                request,
                now=NOW + timedelta(milliseconds=index),
            )
            return "ok"
        except AgentRequestReplayError:
            return "replay"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    assert results.count("ok") == 1
    assert results.count("replay") == 7
