from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from hms_gpt_vps.agent_https_client import AgentHttpsNetworkError
from hms_gpt_vps.agent_runtime_session import (
    AgentCommandAmbiguousError,
    AgentExecutionResponse,
    AgentRuntimeSession,
    AgentRuntimeSessionError,
)
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
    AgentDeviceCredential,
    AgentAuthenticationError,
    _canonical_json,
    sign_bridge_command,
)
from hms_gpt_vps.idempotency_store import IdempotencyStore


FIXED_NOW = datetime(2026, 8, 23, 11, 30, tzinfo=timezone.utc)


def credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id="hms-01",
        device_id="device-01",
        secret=b"S" * 32,
    )


def command(*, request_id: str = "req-01") -> AgentCommandEnvelope:
    return AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id=request_id,
        instance_id="hms-01",
        action="workspace.read",
        params={"path": "hello.txt"},
        deadline_at=FIXED_NOW + timedelta(minutes=5),
    )


class FakeHttp:
    def __init__(self) -> None:
        self.credential = credential()
        self.boot_id = "boot-01"
        self.connection_epoch = 7
        self.poll_responses: list[dict] = []
        self.hello_payloads: list[dict] = []
        self.heartbeat_payloads: list[dict] = []
        self.poll_payloads: list[dict] = []
        self.result_payloads: list[dict] = []
        self.fail_result_once = False

    def _identity_ack(self) -> dict:
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "accepted": True,
            "instance_id": "hms-01",
            "device_id": "device-01",
            "connection_epoch": 7,
        }

    def hello(self, payload, **_kwargs):  # type: ignore[no-untyped-def]
        self.hello_payloads.append(dict(payload))
        return self._identity_ack()

    def heartbeat(self, payload, **_kwargs):  # type: ignore[no-untyped-def]
        self.heartbeat_payloads.append(dict(payload))
        return self._identity_ack()

    def poll(self, payload, **_kwargs):  # type: ignore[no-untyped-def]
        self.poll_payloads.append(dict(payload))
        if self.poll_responses:
            return self.poll_responses.pop(0)
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "instance_id": "hms-01",
            "command": None,
        }

    def submit_result(self, payload, **_kwargs):  # type: ignore[no-untyped-def]
        self.result_payloads.append(dict(payload))
        if self.fail_result_once:
            self.fail_result_once = False
            raise AgentHttpsNetworkError("Bridge HTTPS request failed")
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "accepted": True,
            "instance_id": "hms-01",
            "request_id": payload["request_id"],
        }


def poll_with(signed) -> dict:  # type: ignore[no-untyped-def]
    return {
        "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
        "instance_id": "hms-01",
        "command": signed.to_dict(),
    }


def test_hello_and_heartbeat_bind_exact_runtime_identity(tmp_path) -> None:
    http = FakeHttp()
    session = AgentRuntimeSession(
        http,  # type: ignore[arg-type]
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        lambda _command: AgentExecutionResponse("ok", {}),
    )

    session.hello()
    session.heartbeat()

    assert http.hello_payloads[0]["instance_id"] == "hms-01"
    assert http.hello_payloads[0]["device_id"] == "device-01"
    assert http.hello_payloads[0]["boot_id"] == "boot-01"
    assert http.hello_payloads[0]["connection_epoch"] == 7
    assert sorted(http.hello_payloads[0]["capabilities"]) == sorted(
        http.heartbeat_payloads[0]["capabilities"]
    )
    assert http.heartbeat_payloads[0]["status"] == "healthy"


def test_poll_with_no_command_never_calls_executor(tmp_path) -> None:
    calls = []
    session = AgentRuntimeSession(
        FakeHttp(),  # type: ignore[arg-type]
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        lambda value: calls.append(value) or AgentExecutionResponse("ok", {}),
    )

    assert session.poll_once(now=FIXED_NOW) is None
    assert calls == []


def test_signed_command_executes_once_completes_locally_then_submits_result(tmp_path) -> None:
    http = FakeHttp()
    signed = sign_bridge_command(credential(), command())
    http.poll_responses.append(poll_with(signed))
    calls = []

    def execute(value: AgentCommandEnvelope) -> AgentExecutionResponse:
        calls.append(value.request_id)
        return AgentExecutionResponse(
            "ok",
            {"sha256": "a" * 64, "size": 5},
        )

    session = AgentRuntimeSession(
        http,  # type: ignore[arg-type]
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        execute,
    )
    result = session.poll_once(now=FIXED_NOW)

    assert result is not None
    assert result.outcome == "ok"
    assert calls == ["req-01"]
    assert len(http.result_payloads) == 1
    assert http.result_payloads[0]["request_id"] == "req-01"
    assert http.result_payloads[0]["response"]["sha256"] == "a" * 64


def test_lost_result_post_redelivery_resends_cached_result_without_reexecution(tmp_path) -> None:
    http = FakeHttp()
    signed = sign_bridge_command(credential(), command())
    http.poll_responses.extend([poll_with(signed), poll_with(signed)])
    http.fail_result_once = True
    calls = []

    def execute(value: AgentCommandEnvelope) -> AgentExecutionResponse:
        calls.append(value.request_id)
        return AgentExecutionResponse("ok", {"proof": "stable"})

    session = AgentRuntimeSession(
        http,  # type: ignore[arg-type]
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        execute,
    )

    with pytest.raises(AgentHttpsNetworkError):
        session.poll_once(now=FIXED_NOW)

    replay = session.poll_once(now=FIXED_NOW + timedelta(seconds=1))
    assert replay is not None
    assert replay.response == {"proof": "stable"}
    assert calls == ["req-01"]
    assert len(http.result_payloads) == 2
    assert http.result_payloads[0] == http.result_payloads[1]


def test_unresolved_local_claim_blocks_automatic_reexecution(tmp_path) -> None:
    http = FakeHttp()
    signed = sign_bridge_command(credential(), command())
    http.poll_responses.append(poll_with(signed))
    store = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    session = AgentRuntimeSession(
        http,  # type: ignore[arg-type]
        store,
        lambda _value: (_ for _ in ()).throw(AssertionError("must not execute")),
    )
    command_hash = hashlib.sha256(_canonical_json(command().to_dict())).hexdigest()
    store.claim(
        session._idempotency_namespace,
        "req-01",
        command_hash,
        now=FIXED_NOW - timedelta(seconds=1),
    )

    with pytest.raises(AgentCommandAmbiguousError, match="automatic replay is blocked"):
        session.poll_once(now=FIXED_NOW)
    assert http.result_payloads == []


def test_bad_bridge_signature_never_reaches_executor(tmp_path) -> None:
    http = FakeHttp()
    signed = sign_bridge_command(credential(), command())
    payload = signed.to_dict()
    payload["signature"] = "0" * 64
    http.poll_responses.append(
        {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "instance_id": "hms-01",
            "command": payload,
        }
    )
    calls = []
    session = AgentRuntimeSession(
        http,  # type: ignore[arg-type]
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        lambda value: calls.append(value) or AgentExecutionResponse("ok", {}),
    )

    with pytest.raises(AgentAuthenticationError, match="signature mismatch"):
        session.poll_once(now=FIXED_NOW)
    assert calls == []
    assert http.result_payloads == []


def test_executor_exception_text_is_not_returned_to_bridge(tmp_path) -> None:
    http = FakeHttp()
    http.poll_responses.append(poll_with(sign_bridge_command(credential(), command())))
    secret_detail = "C:\\secret\\token.txt APIKEY-DO-NOT-LEAK"

    def execute(_value: AgentCommandEnvelope) -> AgentExecutionResponse:
        raise RuntimeError(secret_detail)

    session = AgentRuntimeSession(
        http,  # type: ignore[arg-type]
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        execute,
    )
    result = session.poll_once(now=FIXED_NOW)

    assert result is not None
    assert result.outcome == "error"
    assert result.response == {"error": "command execution failed"}
    assert secret_detail not in str(http.result_payloads)


def test_result_ack_identity_mismatch_fails_closed_after_local_completion(tmp_path) -> None:
    class BadAckHttp(FakeHttp):
        def submit_result(self, payload, **_kwargs):  # type: ignore[no-untyped-def]
            self.result_payloads.append(dict(payload))
            return {
                "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
                "accepted": True,
                "instance_id": "other-instance",
                "request_id": payload["request_id"],
            }

    http = BadAckHttp()
    http.poll_responses.append(poll_with(sign_bridge_command(credential(), command())))
    session = AgentRuntimeSession(
        http,  # type: ignore[arg-type]
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        lambda _value: AgentExecutionResponse("ok", {"proof": True}),
    )

    with pytest.raises(AgentRuntimeSessionError, match="instance_id mismatch"):
        session.poll_once(now=FIXED_NOW)
