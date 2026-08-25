from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from hms_gpt_vps.agent_bridge_http_boundary import (
    AgentBridgeHttpBoundary,
    AgentBridgeHttpRequest,
)
from hms_gpt_vps.agent_bridge_service import AgentBridgeService
from hms_gpt_vps.agent_command_store import AgentCommandStore
from hms_gpt_vps.agent_connection_registry import AgentConnectionRegistry
from hms_gpt_vps.agent_health_contract import DEFAULT_REQUIRED_CAPABILITIES
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    MAX_AGENT_BODY_BYTES,
    AgentCommandEnvelope,
    AgentDeviceCredential,
    _canonical_json,
    sign_agent_request,
)


NOW = datetime(2026, 8, 25, 7, 0, tzinfo=timezone.utc)
INSTANCE_ID = "hms-agent-http-01"
DEVICE_ID = "device-01"
BOOT_ID = "boot-01"


def build_boundary(tmp_path: Path):
    db = tmp_path / "db"
    db.mkdir()
    credential = AgentDeviceCredential(
        instance_id=INSTANCE_ID,
        device_id=DEVICE_ID,
        secret=b"S" * 32,
    )

    def request_resolver(instance_id: str, device_id: str):
        if instance_id != INSTANCE_ID or device_id != DEVICE_ID:
            raise KeyError("unknown Agent")
        return credential

    def command_resolver(instance_id: str):
        if instance_id != INSTANCE_ID:
            raise KeyError("unknown Agent")
        return credential

    service = AgentBridgeService(
        AgentConnectionRegistry(db / "presence.sqlite3"),
        AgentCommandStore(db / "commands.sqlite3"),
        request_resolver,
        command_resolver,
    )
    return AgentBridgeHttpBoundary(service), service, credential


def hello_payload() -> dict[str, object]:
    return {
        "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
        "instance_id": INSTANCE_ID,
        "device_id": DEVICE_ID,
        "boot_id": BOOT_ID,
        "connection_epoch": 1,
        "capabilities": sorted(DEFAULT_REQUIRED_CAPABILITIES),
    }


def signed_http_request(
    credential: AgentDeviceCredential,
    path: str,
    payload: dict[str, object],
    *,
    nonce: str,
) -> AgentBridgeHttpRequest:
    body = _canonical_json(payload)
    signed = sign_agent_request(
        credential,
        path=path,
        body=body,
        boot_id=BOOT_ID,
        connection_epoch=1,
        now=NOW,
        nonce=nonce,
    )
    headers = tuple(signed.headers.items()) + (
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        ("Accept", "application/json"),
        ("User-Agent", "HMS-GPT-VPS-Agent/1"),
        ("Cache-Control", "no-store"),
    )
    return AgentBridgeHttpRequest(
        method="POST",
        path=path,
        headers=headers,
        body=body,
    )


def response_json(response) -> dict[str, object]:
    assert response.headers["Content-Type"] == "application/json"
    assert response.headers["Content-Length"] == str(len(response.body))
    return json.loads(response.body.decode("utf-8"))


def test_authenticated_hello_crosses_http_boundary_and_updates_presence(
    tmp_path: Path,
) -> None:
    boundary, service, credential = build_boundary(tmp_path)
    request = signed_http_request(
        credential,
        "/agent/v1/hello",
        hello_payload(),
        nonce="nonce-hello-000000000001",
    )

    response = boundary.handle(request, now=NOW)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    payload = response_json(response)
    assert payload["accepted"] is True
    assert payload["instance_id"] == INSTANCE_ID
    assert payload["device_id"] == DEVICE_ID

    presence = service.get_presence(INSTANCE_ID)
    assert presence is not None
    assert presence.device_id == DEVICE_ID
    assert presence.boot_id == BOOT_ID
    assert presence.connection_epoch == 1


def test_wrong_hmac_returns_secret_free_401_without_presence(
    tmp_path: Path,
) -> None:
    boundary, service, _credential = build_boundary(tmp_path)
    wrong = AgentDeviceCredential(
        instance_id=INSTANCE_ID,
        device_id=DEVICE_ID,
        secret=b"W" * 32,
    )
    request = signed_http_request(
        wrong,
        "/agent/v1/hello",
        hello_payload(),
        nonce="nonce-wrong-000000000001",
    )

    response = boundary.handle(request, now=NOW)
    assert response.status_code == 401
    assert response_json(response) == {"error": "authentication_failed"}
    assert b"WWWW" not in response.body
    assert service.get_presence(INSTANCE_ID) is None


def test_duplicate_case_insensitive_header_is_rejected_before_mutation(
    tmp_path: Path,
) -> None:
    boundary, service, credential = build_boundary(tmp_path)
    request = signed_http_request(
        credential,
        "/agent/v1/hello",
        hello_payload(),
        nonce="nonce-duplicate-000000001",
    )
    auth_value = dict(request.headers)["Authorization"]
    request = AgentBridgeHttpRequest(
        method=request.method,
        path=request.path,
        headers=request.headers + (("authorization", auth_value),),
        body=request.body,
    )

    response = boundary.handle(request, now=NOW)
    assert response.status_code == 400
    assert response_json(response) == {"error": "invalid_http_request"}
    assert service.get_presence(INSTANCE_ID) is None


def test_transfer_encoding_and_length_mismatch_fail_before_hmac_mutation(
    tmp_path: Path,
) -> None:
    boundary, service, credential = build_boundary(tmp_path)
    base = signed_http_request(
        credential,
        "/agent/v1/hello",
        hello_payload(),
        nonce="nonce-shape-0000000000001",
    )

    te = AgentBridgeHttpRequest(
        method=base.method,
        path=base.path,
        headers=base.headers + (("Transfer-Encoding", "chunked"),),
        body=base.body,
    )
    assert boundary.handle(te, now=NOW).status_code == 400

    wrong_length_headers = tuple(
        (key, "1" if key.casefold() == "content-length" else value)
        for key, value in base.headers
    )
    wrong_length = AgentBridgeHttpRequest(
        method=base.method,
        path=base.path,
        headers=wrong_length_headers,
        body=base.body,
    )
    assert boundary.handle(wrong_length, now=NOW).status_code == 400
    assert service.get_presence(INSTANCE_ID) is None


def test_oversized_body_is_413_before_header_or_service_processing(
    tmp_path: Path,
) -> None:
    boundary, service, _credential = build_boundary(tmp_path)
    response = boundary.handle(
        AgentBridgeHttpRequest(
            method="POST",
            path="/agent/v1/hello",
            headers=(),
            body=b"x" * (MAX_AGENT_BODY_BYTES + 1),
        ),
        now=NOW,
    )
    assert response.status_code == 413
    assert response_json(response) == {"error": "request_too_large"}
    assert service.get_presence(INSTANCE_ID) is None


def test_authenticated_poll_returns_exact_signed_pending_command(
    tmp_path: Path,
) -> None:
    boundary, service, credential = build_boundary(tmp_path)
    hello = signed_http_request(
        credential,
        "/agent/v1/hello",
        hello_payload(),
        nonce="nonce-pollhello-000000001",
    )
    assert boundary.handle(hello, now=NOW).status_code == 200

    command = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="request-read-01",
        instance_id=INSTANCE_ID,
        action="workspace.read",
        params={"path": "README.md"},
        deadline_at=NOW + timedelta(minutes=5),
        approved_command_sha256=None,
    )
    service.enqueue_command(command, now=NOW)

    poll_payload = {
        "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
        "instance_id": INSTANCE_ID,
        "device_id": DEVICE_ID,
        "wait_seconds": 0,
        "max_commands": 1,
    }
    poll = signed_http_request(
        credential,
        "/agent/v1/poll",
        poll_payload,
        nonce="nonce-poll-000000000000001",
    )
    response = boundary.handle(poll, now=NOW)
    assert response.status_code == 200
    payload = response_json(response)
    assert payload["instance_id"] == INSTANCE_ID
    signed_command = payload["command"]
    assert isinstance(signed_command, dict)
    assert signed_command["command"]["request_id"] == "request-read-01"
    assert signed_command["command"]["action"] == "workspace.read"
    assert isinstance(signed_command["signature"], str)
    assert len(signed_command["signature"]) == 64
