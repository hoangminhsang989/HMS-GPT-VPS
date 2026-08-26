from pathlib import Path
from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_openai_control_plane_command_flow_qualification as mod
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential

SID = "S-1-5-80-1-2-3-4-5"
SERVICE_PID = 4242
TUNNEL_PID = 5252
AGENT_PID = 6262
SOURCE_COMMIT = "4" * 40
CONTENT_SHA256 = "a" * 64
GENERATION = "d" * 32
LAUNCH_SHA = "e" * 64


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


def request():
    return mod.BridgeExternalMcpCommandFlowQualificationRequest(
        guest_credential=PowerShellDirectCredential(username="Administrator", password="secret"),
        source_commit=SOURCE_COMMIT,
        path="README.md",
        expected_content_sha256=CONTENT_SHA256,
        challenge_path=Path("openai-origin-challenge.json"),
        external_timeout_seconds=60.0,
    )


def tunnel_evidence(**overrides):
    value = {
        "ready": True,
        "service_process_id": SERVICE_PID,
        "tunnel_process_id": TUNNEL_PID,
        "tunnel_parent_process_id": SERVICE_PID,
        "tunnel_executable_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12\tunnel-client-runtime.exe",
        "tunnel_executable_sha256": "b" * 64,
        "health_attempt_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-" + GENERATION,
        "health_url_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-" + GENERATION + r"\health-url.txt",
        "health_base_url": "http://127.0.0.1:54321",
        "health_listener_host": "127.0.0.1",
        "health_listener_port": 54321,
        "readiness_url": "http://127.0.0.1:54321/readyz",
        "readiness_status_code": 200,
        "readiness_body_class": "mcp_auth_required",
        "mcp_ingress_generation": GENERATION,
        "openai_origin_launch_profile_proven": True,
        "launch_command_line_sha256": LAUNCH_SHA,
    }
    value.update(overrides)
    return value


def observer_evidence(challenge, **overrides):
    value = {
        "ready": True,
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
        "agent_result_sha256": "d" * 64,
        "pairing_record_consumed": True,
        "principal_binding_proven": True,
        "control_session_proven": True,
        "dispatch_intent_proven": True,
        "idempotency_completion_receipt_proven": True,
        "agent_command_result_proven": True,
        "authenticated_principal_control_path_proven": True,
        "mcp_ingress_provenance_present": True,
        "mcp_ingress_generation": GENERATION,
        "mcp_adapter_invocation_proven": True,
        "openai_control_plane_origin_proven": False,
        "secure_tunnel_generation_proven": False,
        "full_bridge_command_flow_proven": False,
    }
    value.update(overrides)
    return value


def install_success(monkeypatch, *, second_tunnel=None):
    order = []
    config = Config(order)
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", Config)
    monkeypatch.setattr(mod, "derive_hms_bridge_service_sid", lambda: SID)
    monkeypatch.setattr(mod, "load_protected_bridge_service_runtime_config", lambda: config)
    identities = iter([
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
    ])
    monkeypatch.setattr(mod, "prove_hms_bridge_provisioning_identity", lambda: order.append("identity") or next(identities))
    monkeypatch.setattr(mod, "_load_and_verify_package", lambda: order.append("package") or object())
    guest = {"health_boot_id": "boot-1", "process_id": AGENT_PID}
    monkeypatch.setattr(mod, "_observe_guest_agent", lambda *a: order.append("guest.observe") or dict(guest))
    monkeypatch.setattr(mod, "start_hms_bridge_for_qualification", lambda *a: order.append("service.start") or {"process_id": SERVICE_PID})
    tunnels = iter([tunnel_evidence(), second_tunnel or tunnel_evidence()])
    monkeypatch.setattr(
        mod,
        "qualify_running_secure_mcp_tunnel_with_openai_origin_profile",
        lambda **k: order.append("tunnel.origin") or next(tunnels),
    )
    hello = SimpleNamespace(device_id="device-1", boot_id="boot-1", connection_epoch=7)
    monkeypatch.setattr(mod, "_wait_for_authenticated_hello", lambda *a, **k: order.append("hello") or hello)
    monkeypatch.setattr(mod, "_wait_for_heartbeat_generation_stability", lambda *a, **k: order.append("heartbeat") or hello)
    monkeypatch.setattr(mod, "write_json_create_only", lambda *a, **k: order.append("challenge.publish"))

    def wait_external(runtime_root, challenge, **kwargs):
        order.append("external.wait")
        return observer_evidence(challenge)

    monkeypatch.setattr(mod, "_wait_for_external_observation", wait_external)
    monkeypatch.setattr(mod, "_read_presence_read_only", lambda *a, **k: order.append("presence") or hello)
    monkeypatch.setattr(mod, "stop_hms_bridge_after_qualification", lambda *a: order.append("service.stop") or {"ready": True})
    return order


def test_openai_control_plane_origin_is_narrowly_proven(monkeypatch):
    order = install_success(monkeypatch)
    result = mod.qualify_openai_control_plane_mcp_read(request())
    assert result["mcp_adapter_invocation_proven"] is True
    assert result["secure_tunnel_generation_proven"] is True
    assert result["openai_tunnel_launch_profile_proven"] is True
    assert result["openai_control_plane_origin_proven"] is True
    assert result["chatgpt_ui_origin_proven"] is False
    assert result["full_bridge_command_flow_proven"] is False
    assert result["runner_invoked_mcp"] is False
    assert result["runner_enqueued_agent_command"] is False
    assert result["openai_tunnel_upstream_commit"] == "881c9a8fed7cccbe6607cd419863bbca506b8215"
    assert order[-2:] == ["service.stop", "identity"]


def test_origin_launch_profile_drift_fails_closed_and_stops(monkeypatch):
    order = install_success(monkeypatch, second_tunnel=tunnel_evidence(launch_command_line_sha256="f" * 64))
    with pytest.raises(
        mod.BridgeExternalMcpCommandFlowQualificationError,
        match="launch/generation authority changed",
    ):
        mod.qualify_openai_control_plane_mcp_read(request())
    assert "service.stop" in order


def test_missing_origin_launch_proof_fails_closed_and_stops(monkeypatch):
    order = install_success(monkeypatch)
    first = tunnel_evidence(openai_origin_launch_profile_proven=False)
    tunnels = iter([first, tunnel_evidence()])
    monkeypatch.setattr(
        mod,
        "qualify_running_secure_mcp_tunnel_with_openai_origin_profile",
        lambda **k: order.append("tunnel.origin") or next(tunnels),
    )
    with pytest.raises(
        mod.BridgeExternalMcpCommandFlowQualificationError,
        match="launch profile was not proven",
    ):
        mod.qualify_openai_control_plane_mcp_read(request())
    assert "service.stop" in order
