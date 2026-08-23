from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    MAX_AGENT_BODY_BYTES,
    AgentAuthenticationError,
    AgentBodyIntegrityError,
    AgentClockSkewError,
    AgentCommandEnvelope,
    AgentCommandResult,
    AgentDeviceCredential,
    AgentSignedRequest,
    AgentTransportError,
    sign_agent_request,
    sign_bridge_command,
    verify_agent_request,
    verify_bridge_command,
)


NOW = datetime(2026, 8, 23, 11, 0, tzinfo=timezone.utc)
CREDENTIAL = AgentDeviceCredential(
    instance_id="hms-01",
    device_id="device-01",
    secret=b"D" * 32,
)
BOOT_ID = "boot-01"
NONCE = "agent-nonce-0123456789"


def test_device_credential_repr_does_not_reveal_secret() -> None:
    assert "DDDD" not in repr(CREDENTIAL)
    CREDENTIAL.validate()


def test_signed_agent_request_round_trip() -> None:
    signed = sign_agent_request(
        CREDENTIAL,
        path="/agent/v1/heartbeat",
        body=b'{"status":"ok"}',
        boot_id=BOOT_ID,
        connection_epoch=7,
        now=NOW,
        nonce=NONCE,
    )
    verified = verify_agent_request(CREDENTIAL, signed, now=NOW + timedelta(seconds=30))

    assert verified.device_id == CREDENTIAL.device_id
    assert verified.instance_id == CREDENTIAL.instance_id
    assert verified.boot_id == BOOT_ID
    assert verified.connection_epoch == 7
    assert verified.nonce == NONCE
    assert "DDDD" not in repr(signed)


def test_agent_request_body_tamper_is_rejected_before_hmac_acceptance() -> None:
    signed = sign_agent_request(
        CREDENTIAL,
        path="/agent/v1/result",
        body=b"original",
        boot_id=BOOT_ID,
        connection_epoch=1,
        now=NOW,
        nonce=NONCE,
    )
    tampered = AgentSignedRequest(
        method=signed.method,
        path=signed.path,
        body=b"tampered",
        headers=signed.headers,
    )
    with pytest.raises(AgentBodyIntegrityError, match="SHA-256"):
        verify_agent_request(CREDENTIAL, tampered, now=NOW)


def test_agent_request_header_tamper_is_rejected() -> None:
    signed = sign_agent_request(
        CREDENTIAL,
        path="/agent/v1/poll",
        body=b"{}",
        boot_id=BOOT_ID,
        connection_epoch=1,
        now=NOW,
        nonce=NONCE,
    )
    headers = dict(signed.headers)
    headers["X-HMS-Connection-Epoch"] = "2"
    tampered = AgentSignedRequest(
        method=signed.method,
        path=signed.path,
        body=signed.body,
        headers=headers,
    )
    with pytest.raises(AgentAuthenticationError, match="HMAC"):
        verify_agent_request(CREDENTIAL, tampered, now=NOW)


def test_agent_request_wrong_instance_credential_is_rejected() -> None:
    signed = sign_agent_request(
        CREDENTIAL,
        path="/agent/v1/heartbeat",
        body=b"{}",
        boot_id=BOOT_ID,
        connection_epoch=1,
        now=NOW,
        nonce=NONCE,
    )
    other = AgentDeviceCredential(
        instance_id="hms-02",
        device_id=CREDENTIAL.device_id,
        secret=CREDENTIAL.secret,
    )
    with pytest.raises(AgentAuthenticationError, match="instance_id"):
        verify_agent_request(other, signed, now=NOW)


def test_agent_request_clock_skew_is_bounded() -> None:
    signed = sign_agent_request(
        CREDENTIAL,
        path="/agent/v1/heartbeat",
        body=b"{}",
        boot_id=BOOT_ID,
        connection_epoch=1,
        now=NOW,
        nonce=NONCE,
    )
    with pytest.raises(AgentClockSkewError, match="clock skew"):
        verify_agent_request(CREDENTIAL, signed, now=NOW + timedelta(seconds=91))


def test_agent_request_rejects_unapproved_endpoint_and_oversized_body() -> None:
    with pytest.raises(AgentTransportError, match="endpoint"):
        sign_agent_request(
            CREDENTIAL,
            path="/agent/v1/arbitrary",
            body=b"{}",
            boot_id=BOOT_ID,
            connection_epoch=1,
            now=NOW,
            nonce=NONCE,
        )
    with pytest.raises(AgentTransportError, match="maximum size"):
        sign_agent_request(
            CREDENTIAL,
            path="/agent/v1/result",
            body=b"x" * (MAX_AGENT_BODY_BYTES + 1),
            boot_id=BOOT_ID,
            connection_epoch=1,
            now=NOW,
            nonce=NONCE,
        )


def base_command() -> AgentCommandEnvelope:
    return AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="request-01",
        instance_id=CREDENTIAL.instance_id,
        action="workspace.write",
        params={"path": "proof.txt", "content": "hello", "mode": "create"},
        deadline_at=NOW + timedelta(minutes=2),
    )


def test_signed_bridge_command_round_trip() -> None:
    command = base_command()
    signed = sign_bridge_command(CREDENTIAL, command)
    verified = verify_bridge_command(CREDENTIAL, signed, now=NOW)
    assert verified == command
    assert "DDDD" not in repr(signed)


def test_bridge_command_tamper_is_rejected() -> None:
    command = base_command()
    signed = sign_bridge_command(CREDENTIAL, command)
    tampered_command = replace(
        command,
        params={"path": "proof.txt", "content": "tampered", "mode": "create"},
    )
    tampered = replace(signed, command=tampered_command)
    with pytest.raises(AgentAuthenticationError, match="HMAC"):
        verify_bridge_command(CREDENTIAL, tampered, now=NOW)


def test_bridge_command_deadline_is_enforced() -> None:
    command = replace(base_command(), deadline_at=NOW + timedelta(seconds=1))
    signed = sign_bridge_command(CREDENTIAL, command)
    with pytest.raises(AgentAuthenticationError, match="deadline"):
        verify_bridge_command(CREDENTIAL, signed, now=NOW + timedelta(seconds=1))


def test_destructive_approval_hash_binds_exact_command() -> None:
    command = base_command()
    approved = replace(command, approved_command_sha256=command.command_sha256())
    approved.validate()
    assert approved.is_destructive_approved() is True

    changed = replace(
        approved,
        params={"path": "other.txt", "content": "hello", "mode": "replace"},
    )
    with pytest.raises(AgentTransportError, match="does not match exact command"):
        changed.validate()


def test_command_rejects_unknown_action() -> None:
    command = replace(base_command(), action="process.shell")
    with pytest.raises(AgentTransportError, match="unsupported"):
        command.validate()


def test_command_result_is_json_bounded_contract() -> None:
    result = AgentCommandResult(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="request-01",
        instance_id="hms-01",
        outcome="ok",
        response={"sha256": "a" * 64, "size": 5},
        completed_at=NOW,
    )
    payload = result.to_dict()
    assert payload["outcome"] == "ok"
    assert payload["response"]["size"] == 5
