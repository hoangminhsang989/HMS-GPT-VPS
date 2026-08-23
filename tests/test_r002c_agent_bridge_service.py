from __future__ import annotations

from datetime import datetime, timedelta, timezone
import secrets

import pytest

from hms_gpt_vps.agent_bridge_service import AgentBridgeService
from hms_gpt_vps.agent_command_store import (
    AgentCommandConflictError,
    AgentCommandState,
    AgentCommandStore,
    AgentCommandStoreError,
)
from hms_gpt_vps.agent_connection_registry import (
    AgentConnectionRegistry,
    AgentRequestReplayError,
)
from hms_gpt_vps.agent_health_contract import DEFAULT_REQUIRED_CAPABILITIES
from hms_gpt_vps.agent_transport_codec import parse_signed_agent_command
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentAuthenticationError,
    AgentCommandEnvelope,
    AgentCommandResult,
    AgentDeviceCredential,
    AgentSignedRequest,
    AgentTransportError,
    _canonical_json,
    sign_agent_request,
    verify_bridge_command,
)


NOW = datetime(2026, 8, 23, 11, 30, tzinfo=timezone.utc)


def credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id="hms-01",
        device_id="device-01",
        secret=b"S" * 32,
    )


def build_service(tmp_path) -> AgentBridgeService:
    expected = credential()

    def request_resolver(instance_id: str, device_id: str) -> AgentDeviceCredential:
        if instance_id != expected.instance_id or device_id != expected.device_id:
            raise KeyError("unknown")
        return expected

    def command_resolver(instance_id: str) -> AgentDeviceCredential:
        if instance_id != expected.instance_id:
            raise KeyError("unknown")
        return expected

    return AgentBridgeService(
        AgentConnectionRegistry(tmp_path / "presence.sqlite3"),
        AgentCommandStore(tmp_path / "commands.sqlite3"),
        request_resolver,
        command_resolver,
    )


def sign_request(
    path: str,
    payload: dict,
    *,
    now: datetime = NOW,
    nonce: str | None = None,
    epoch: int = 1,
    boot_id: str = "boot-01",
) -> AgentSignedRequest:
    return sign_agent_request(
        credential(),
        path=path,
        body=_canonical_json(payload),
        boot_id=boot_id,
        connection_epoch=epoch,
        now=now,
        nonce=nonce,
    )


def hello_payload(*, epoch: int = 1, boot_id: str = "boot-01") -> dict:
    return {
        "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
        "instance_id": "hms-01",
        "device_id": "device-01",
        "boot_id": boot_id,
        "connection_epoch": epoch,
        "capabilities": sorted(DEFAULT_REQUIRED_CAPABILITIES),
    }


def poll_payload() -> dict:
    return {
        "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
        "instance_id": "hms-01",
        "device_id": "device-01",
        "wait_seconds": 20,
        "max_commands": 1,
    }


def test_signed_hello_creates_presence_and_returns_exact_ack(tmp_path) -> None:
    service = build_service(tmp_path)
    response = service.handle(
        sign_request("/agent/v1/hello", hello_payload()),
        now=NOW,
    )

    assert response == {
        "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
        "accepted": True,
        "instance_id": "hms-01",
        "device_id": "device-01",
        "connection_epoch": 1,
    }
    presence = service.registry.get_presence("hms-01")
    assert presence is not None
    assert presence.device_id == "device-01"
    assert presence.boot_id == "boot-01"
    assert presence.connection_epoch == 1


def test_hmac_valid_but_schema_invalid_body_does_not_consume_nonce(tmp_path) -> None:
    service = build_service(tmp_path)
    nonce = secrets.token_urlsafe(32)
    malformed = hello_payload()
    del malformed["capabilities"]

    with pytest.raises(AgentTransportError, match="fields do not match schema"):
        service.handle(
            sign_request(
                "/agent/v1/hello",
                malformed,
                nonce=nonce,
            ),
            now=NOW,
        )
    assert service.registry.get_presence("hms-01") is None

    response = service.handle(
        sign_request(
            "/agent/v1/hello",
            hello_payload(),
            nonce=nonce,
        ),
        now=NOW,
    )
    assert response["accepted"] is True


def test_bad_hmac_fails_before_invalid_json_is_parsed_or_presence_mutates(tmp_path) -> None:
    service = build_service(tmp_path)
    signed = sign_agent_request(
        credential(),
        path="/agent/v1/hello",
        body=b"not-json",
        boot_id="boot-01",
        connection_epoch=1,
        now=NOW,
    )
    headers = dict(signed.headers)
    headers["Authorization"] = "HMS-Agent-HMAC-SHA256 " + ("0" * 64)
    tampered = AgentSignedRequest(
        method=signed.method,
        path=signed.path,
        body=signed.body,
        headers=headers,
    )

    with pytest.raises(AgentAuthenticationError, match="HMAC signature mismatch"):
        service.handle(tampered, now=NOW)
    assert service.registry.get_presence("hms-01") is None


def test_duplicate_case_insensitive_identity_header_is_rejected(tmp_path) -> None:
    service = build_service(tmp_path)
    signed = sign_request("/agent/v1/hello", hello_payload())
    headers = dict(signed.headers)
    headers["x-hms-device-id"] = headers["X-HMS-Device-Id"]
    duplicated = AgentSignedRequest(
        method=signed.method,
        path=signed.path,
        body=signed.body,
        headers=headers,
    )

    with pytest.raises(AgentAuthenticationError, match="duplicate"):
        service.handle(duplicated, now=NOW)
    assert service.registry.get_presence("hms-01") is None


def test_command_poll_redelivery_result_completion_and_idempotent_ack(tmp_path) -> None:
    service = build_service(tmp_path)
    service.handle(sign_request("/agent/v1/hello", hello_payload()), now=NOW)

    command = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        action="workspace.read",
        params={"path": "hello.txt"},
        deadline_at=NOW + timedelta(minutes=5),
    )
    queued = service.enqueue_command(command, now=NOW)
    assert queued.state is AgentCommandState.PENDING

    first_poll = service.handle(
        sign_request(
            "/agent/v1/poll",
            poll_payload(),
            now=NOW + timedelta(seconds=1),
        ),
        now=NOW + timedelta(seconds=1),
    )
    assert first_poll["command"] is not None
    signed_command = parse_signed_agent_command(first_poll["command"])
    verified_command = verify_bridge_command(
        credential(),
        signed_command,
        now=NOW + timedelta(seconds=1),
    )
    assert verified_command.request_id == "req-01"

    second_poll = service.handle(
        sign_request(
            "/agent/v1/poll",
            poll_payload(),
            now=NOW + timedelta(seconds=2),
        ),
        now=NOW + timedelta(seconds=2),
    )
    assert second_poll["command"] == first_poll["command"]

    result = AgentCommandResult(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        outcome="ok",
        response={"sha256": "a" * 64, "size": 5},
        completed_at=NOW + timedelta(seconds=3),
    )
    result_ack = service.handle(
        sign_request(
            "/agent/v1/result",
            result.to_dict(),
            now=NOW + timedelta(seconds=3),
        ),
        now=NOW + timedelta(seconds=3),
    )
    assert result_ack == {
        "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
        "accepted": True,
        "instance_id": "hms-01",
        "request_id": "req-01",
    }
    status = service.get_command_status("hms-01", "req-01")
    assert status is not None
    assert status.state is AgentCommandState.COMPLETED
    assert status.result == result

    replay_ack = service.handle(
        sign_request(
            "/agent/v1/result",
            result.to_dict(),
            now=NOW + timedelta(seconds=4),
        ),
        now=NOW + timedelta(seconds=4),
    )
    assert replay_ack == result_ack

    after_complete = service.handle(
        sign_request(
            "/agent/v1/poll",
            poll_payload(),
            now=NOW + timedelta(seconds=5),
        ),
        now=NOW + timedelta(seconds=5),
    )
    assert after_complete["command"] is None


def test_different_result_for_completed_request_conflicts(tmp_path) -> None:
    service = build_service(tmp_path)
    service.handle(sign_request("/agent/v1/hello", hello_payload()), now=NOW)
    command = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        action="workspace.read",
        params={"path": "hello.txt"},
        deadline_at=NOW + timedelta(minutes=5),
    )
    service.enqueue_command(command, now=NOW)
    first = AgentCommandResult(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        outcome="ok",
        response={"value": 1},
        completed_at=NOW + timedelta(seconds=1),
    )
    service.handle(
        sign_request(
            "/agent/v1/result",
            first.to_dict(),
            now=NOW + timedelta(seconds=1),
        ),
        now=NOW + timedelta(seconds=1),
    )
    conflicting = AgentCommandResult(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        outcome="ok",
        response={"value": 2},
        completed_at=first.completed_at,
    )
    with pytest.raises(AgentCommandConflictError, match="different completed result"):
        service.handle(
            sign_request(
                "/agent/v1/result",
                conflicting.to_dict(),
                now=NOW + timedelta(seconds=2),
            ),
            now=NOW + timedelta(seconds=2),
        )


def test_expired_command_is_not_returned_to_agent(tmp_path) -> None:
    service = build_service(tmp_path)
    service.handle(sign_request("/agent/v1/hello", hello_payload()), now=NOW)
    command = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-expired",
        instance_id="hms-01",
        action="git.status",
        params={},
        deadline_at=NOW + timedelta(seconds=1),
    )
    service.enqueue_command(command, now=NOW)

    response = service.handle(
        sign_request(
            "/agent/v1/poll",
            poll_payload(),
            now=NOW + timedelta(seconds=2),
        ),
        now=NOW + timedelta(seconds=2),
    )
    assert response["command"] is None
    status = service.get_command_status("hms-01", "req-expired")
    assert status is not None
    assert status.state is AgentCommandState.EXPIRED


def test_replayed_signed_request_nonce_is_rejected(tmp_path) -> None:
    service = build_service(tmp_path)
    signed = sign_request("/agent/v1/hello", hello_payload())
    service.handle(signed, now=NOW)
    with pytest.raises(AgentRequestReplayError, match="already been used"):
        service.handle(signed, now=NOW)


def test_same_request_id_cannot_be_rebound_to_different_command(tmp_path) -> None:
    service = build_service(tmp_path)
    first = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        action="workspace.read",
        params={"path": "a.txt"},
        deadline_at=NOW + timedelta(minutes=5),
    )
    second = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        action="workspace.read",
        params={"path": "b.txt"},
        deadline_at=first.deadline_at,
    )
    service.enqueue_command(first, now=NOW)
    with pytest.raises(AgentCommandConflictError, match="different Agent command"):
        service.enqueue_command(second, now=NOW)


def test_command_store_never_creates_missing_security_parent(tmp_path) -> None:
    parent = tmp_path / "missing"
    with pytest.raises(AgentCommandStoreError, match="parent must already exist"):
        AgentCommandStore(parent / "commands.sqlite3")
    assert parent.exists() is False
