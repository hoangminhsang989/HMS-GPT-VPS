from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_external_mcp_command_flow_qualification as mod
from hms_gpt_vps.idempotency_store import IdempotencyState
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential

SID = "S-1-5-80-1-2-3-4-5"
SERVICE_PID = 4242
TUNNEL_PID = 5252
AGENT_PID = 6262
SOURCE_COMMIT = "4" * 40
CONTENT_SHA256 = "a" * 64


class Config:
    instance_id = "instance-1"
    runtime_root = r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime"

    def __init__(self, order):
        self.order = order

    def validate(self):
        self.order.append("config.validate")

    def to_runtime_config(self, sid):
        assert sid == SID
        self.order.append("config.runtime")
        return object()


class FakeIntent:
    def __init__(self, instance_id, request_id, session_id, request_sha256):
        self.instance_id = instance_id
        self.request_id = request_id
        self.session_id = session_id
        self.request_sha256 = request_sha256

    @classmethod
    def from_row(cls, row):
        if row.get("invalid"):
            raise ValueError("invalid dispatch row")
        return cls(
            row["instance_id"],
            row["request_id"],
            row["session_id"],
            row["request_sha256"],
        )


def request(**overrides):
    values = {
        "guest_credential": PowerShellDirectCredential(
            username="Administrator",
            password="secret",
        ),
        "source_commit": SOURCE_COMMIT,
        "path": "README.md",
        "expected_content_sha256": CONTENT_SHA256,
        "challenge_path": Path("external-challenge.json"),
        "external_timeout_seconds": 60.0,
    }
    values.update(overrides)
    return mod.BridgeExternalMcpCommandFlowQualificationRequest(**values)


def tunnel_evidence(**overrides):
    value = {
        "ready": True,
        "service_process_id": SERVICE_PID,
        "tunnel_process_id": TUNNEL_PID,
        "tunnel_parent_process_id": SERVICE_PID,
        "tunnel_executable_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12\tunnel-client-runtime.exe",
        "tunnel_executable_sha256": "b" * 64,
        "health_attempt_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-" + "d" * 32,
        "health_url_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-" + "d" * 32 + r"\health-url.txt",
        "health_base_url": "http://127.0.0.1:54321",
        "health_listener_host": "127.0.0.1",
        "health_listener_port": 54321,
        "readiness_url": "http://127.0.0.1:54321/readyz",
        "readiness_status_code": 200,
        "readiness_body_class": "mcp_auth_required",
    }
    value.update(overrides)
    return value


def observer_evidence(challenge, **overrides):
    value = {
        "ready": True,
        "status": "PRINCIPAL_BOUND_READ_DURABLE_AUTHORITY_OBSERVED",
        "challenge_id": challenge.challenge_id,
        "source_commit": challenge.source_commit,
        "instance_id": challenge.instance_id,
        "request_id": challenge.request_id,
        "path": challenge.path,
        "expected_content_sha256": challenge.expected_content_sha256,
        "workspace_content_size": 123,
        "workspace_content_encoding": "utf-8",
        "principal_sha256": "c" * 64,
        "pair_id": "pair-1",
        "session_id": "session-1",
        "session_epoch": 7,
        "agent_command_action": "workspace.read",
        "agent_result_outcome": "ok",
        "agent_result_sha256": "d" * 64,
        "pairing_record_consumed": True,
        "principal_binding_proven": True,
        "control_session_proven": True,
        "dispatch_intent_proven": True,
        "idempotency_completion_receipt_proven": True,
        "agent_command_result_proven": True,
        "authenticated_principal_control_path_proven": True,
        "mcp_adapter_invocation_proven": False,
        "openai_control_plane_origin_proven": False,
        "secure_tunnel_generation_proven": False,
        "full_bridge_command_flow_proven": False,
    }
    value.update(overrides)
    return value


def install_success(monkeypatch):
    order = []
    config = Config(order)
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", Config)
    monkeypatch.setattr(mod, "derive_hms_bridge_service_sid", lambda: SID)
    monkeypatch.setattr(
        mod,
        "load_protected_bridge_service_runtime_config",
        lambda: config,
    )
    identities = iter(
        [
            {
                "service_sid": SID,
                "service_state": "Stopped",
                "service_start_mode": "Manual",
            },
            {
                "service_sid": SID,
                "service_state": "Stopped",
                "service_start_mode": "Manual",
            },
        ]
    )
    monkeypatch.setattr(
        mod,
        "prove_hms_bridge_provisioning_identity",
        lambda: order.append("identity") or next(identities),
    )
    monkeypatch.setattr(
        mod,
        "_load_and_verify_package",
        lambda: order.append("package") or object(),
    )
    guest = {"health_boot_id": "boot-1", "process_id": AGENT_PID}
    monkeypatch.setattr(
        mod,
        "_observe_guest_agent",
        lambda *a: order.append("guest.observe") or dict(guest),
    )
    monkeypatch.setattr(
        mod,
        "start_hms_bridge_for_qualification",
        lambda *a: order.append("service.start") or {"process_id": SERVICE_PID},
    )
    tunnel_values = iter([tunnel_evidence(), tunnel_evidence()])
    monkeypatch.setattr(
        mod,
        "qualify_running_secure_mcp_tunnel",
        lambda **k: order.append("tunnel.probe") or next(tunnel_values),
    )
    hello = SimpleNamespace(
        device_id="device-1",
        boot_id="boot-1",
        connection_epoch=7,
    )
    monkeypatch.setattr(
        mod,
        "_wait_for_authenticated_hello",
        lambda *a, **k: order.append("hello") or hello,
    )
    monkeypatch.setattr(
        mod,
        "_wait_for_heartbeat_generation_stability",
        lambda *a, **k: order.append("heartbeat") or hello,
    )
    published = {}
    monkeypatch.setattr(
        mod,
        "write_json_create_only",
        lambda path, payload, **kwargs: order.append("challenge.publish")
        or published.update(path=path, payload=payload, kwargs=kwargs),
    )

    def wait_for_external(runtime_root, challenge, **kwargs):
        order.append("external.wait")
        return observer_evidence(challenge)

    monkeypatch.setattr(mod, "_wait_for_external_observation", wait_for_external)
    monkeypatch.setattr(
        mod,
        "_read_presence_read_only",
        lambda *a, **k: order.append("presence") or hello,
    )
    monkeypatch.setattr(
        mod,
        "stop_hms_bridge_after_qualification",
        lambda *a: order.append("service.stop") or {"ready": True},
    )
    return order, published


def test_request_rejects_noncanonical_authority():
    request().validate()
    for patch in (
        {"source_commit": "ABC"},
        {"path": "../README.md"},
        {"expected_content_sha256": "A" * 64},
        {"external_timeout_seconds": True},
        {"external_timeout_seconds": 901.0},
    ):
        with pytest.raises(Exception):
            request(**patch).validate()


def test_challenge_payload_is_non_secret_and_exact():
    challenge = mod._new_challenge(request(), instance_id="instance-1")
    payload = mod._challenge_payload(challenge)
    assert payload["kind"] == "R002F_EXTERNAL_MCP_READ_CHALLENGE"
    assert payload["tool_name"] == "read_file"
    assert payload["tool_arguments"] == {
        "instance_id": "instance-1",
        "request_id": challenge.request_id,
        "path": "README.md",
    }
    assert payload["challenge"]["source_commit"] == SOURCE_COMMIT
    assert payload["challenge"]["expected_content_sha256"] == CONTENT_SHA256
    assert payload["non_secret"] is True
    assert "TOP-SECRET" not in repr(payload)
    assert "password" not in repr(payload).casefold()


def test_progress_observer_handles_absent_claimed_completed_and_atomic_gap(monkeypatch):
    challenge = mod._new_challenge(request(), instance_id="instance-1")

    @contextmanager
    def connection(*args, **kwargs):
        yield object()

    monkeypatch.setattr(mod, "read_only_connection", connection)
    monkeypatch.setattr(mod, "PrincipalDispatchIntent", FakeIntent)
    monkeypatch.setattr(
        mod.IdempotencyStore,
        "_validate_row",
        staticmethod(lambda row, **kwargs: (row["_state"], None)),
    )
    monkeypatch.setattr(mod, "query_rows", lambda *a, **k: [])
    assert mod._observe_external_progress(Path("C:/runtime"), challenge) == "absent"

    for state, expected in (
        (IdempotencyState.CLAIMED, "claimed"),
        (IdempotencyState.COMPLETED, "completed"),
    ):
        def query_rows(connection, query, params, state=state):
            if "FROM principal_agent_dispatch_claims" in query:
                return [
                    {
                        "instance_id": challenge.instance_id,
                        "request_id": challenge.request_id,
                        "session_id": "session-1",
                        "request_sha256": "e" * 64,
                    }
                ]
            return [{"_state": state}]

        monkeypatch.setattr(mod, "query_rows", query_rows)
        assert mod._observe_external_progress(Path("C:/runtime"), challenge) == expected

    def atomic_gap(connection, query, params):
        if "FROM principal_agent_dispatch_claims" in query:
            return [
                {
                    "instance_id": challenge.instance_id,
                    "request_id": challenge.request_id,
                    "session_id": "session-1",
                    "request_sha256": "e" * 64,
                }
            ]
        return []

    monkeypatch.setattr(mod, "query_rows", atomic_gap)
    with pytest.raises(
        mod.BridgeExternalMcpCommandFlowQualificationError,
        match="atomic idempotency",
    ):
        mod._observe_external_progress(Path("C:/runtime"), challenge)


def test_wait_calls_full_observer_only_after_completed(monkeypatch):
    challenge = mod._new_challenge(request(), instance_id="instance-1")
    states = iter(["absent", "claimed", "completed"])
    calls = []
    monkeypatch.setattr(mod, "_observe_external_progress", lambda *a: next(states))
    monkeypatch.setattr(
        mod,
        "observe_external_mcp_read_durable_authority",
        lambda *a, **k: calls.append("observer") or observer_evidence(challenge),
    )
    ticks = iter([0.0, 0.0, 0.1, 0.2, 0.3])
    result = mod._wait_for_external_observation(
        Path("C:/runtime"),
        challenge,
        timeout_seconds=1.0,
        monotonic=lambda: next(ticks),
        sleeper=lambda seconds: calls.append("sleep"),
    )
    assert result["request_id"] == challenge.request_id
    assert calls == ["sleep", "sleep", "observer"]


def test_external_read_is_bracketed_without_runner_self_call(monkeypatch):
    order, published = install_success(monkeypatch)
    result = mod.qualify_external_mcp_read_with_stable_tunnel(request())
    assert order == [
        "config.validate",
        "config.runtime",
        "package",
        "identity",
        "guest.observe",
        "service.start",
        "tunnel.probe",
        "hello",
        "heartbeat",
        "guest.observe",
        "challenge.publish",
        "external.wait",
        "presence",
        "guest.observe",
        "tunnel.probe",
        "service.stop",
        "identity",
    ]
    assert published["payload"]["tool_name"] == "read_file"
    assert published["payload"]["tool_arguments"]["request_id"] == result["request_id"]
    assert result["durable_external_principal_read_proven"] is True
    assert result["secure_tunnel_generation_proven"] is True
    assert result["runner_invoked_mcp"] is False
    assert result["runner_enqueued_agent_command"] is False
    assert result["mcp_adapter_invocation_proven"] is False
    assert result["openai_control_plane_origin_proven"] is False
    assert result["full_bridge_command_flow_proven"] is False


def test_observer_identity_drift_fails_closed_and_stops(monkeypatch):
    order, _ = install_success(monkeypatch)

    def wait_for_external(runtime_root, challenge, **kwargs):
        order.append("external.wait")
        return observer_evidence(challenge, path="other.txt")

    monkeypatch.setattr(mod, "_wait_for_external_observation", wait_for_external)
    with pytest.raises(
        mod.BridgeExternalMcpCommandFlowQualificationError,
        match="identity differs",
    ):
        mod.qualify_external_mcp_read_with_stable_tunnel(request())
    assert order[-1] == "service.stop"


def test_tunnel_generation_drift_fails_closed_and_stops(monkeypatch):
    order, _ = install_success(monkeypatch)
    tunnel_values = iter(
        [tunnel_evidence(), tunnel_evidence(tunnel_process_id=7777)]
    )
    monkeypatch.setattr(
        mod,
        "qualify_running_secure_mcp_tunnel",
        lambda **k: order.append("tunnel.probe") or next(tunnel_values),
    )
    with pytest.raises(
        mod.BridgeExternalMcpCommandFlowQualificationError,
        match="tunnel generation changed",
    ):
        mod.qualify_external_mcp_read_with_stable_tunnel(request())
    assert "service.stop" in order
