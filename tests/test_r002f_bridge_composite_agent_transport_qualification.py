from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_composite_agent_transport_qualification as mod

SID = "S-1-5-80-1-2-3-4-5"
SERVICE_PID = 4242
TUNNEL_PID = 5252
AGENT_PID = 6262


class Request:
    def __init__(self, order):
        self.order = order
        self.guest_credential = object()
        self.hello_timeout_seconds = 45.0
        self.heartbeat_margin_seconds = 3.0
        self.command_timeout_seconds = 45.0

    def validate(self):
        self.order.append("request.validate")


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


def tunnel_evidence(**overrides):
    value = {
        "ready": True,
        "service_process_id": SERVICE_PID,
        "tunnel_process_id": TUNNEL_PID,
        "tunnel_parent_process_id": SERVICE_PID,
        "tunnel_executable_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12\tunnel-client-runtime.exe",
        "tunnel_executable_sha256": "a" * 64,
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


def _install_success(monkeypatch):
    order = []
    request = Request(order)
    config = Config(order)
    monkeypatch.setattr(mod, "BridgeAgentTransportQualificationRequest", Request)
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", Config)
    monkeypatch.setattr(mod, "derive_hms_bridge_service_sid", lambda: SID)
    monkeypatch.setattr(mod, "load_protected_bridge_service_runtime_config", lambda: config)
    identities = iter([
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
    ])
    monkeypatch.setattr(
        mod,
        "prove_hms_bridge_provisioning_identity",
        lambda: order.append("identity") or next(identities),
    )
    monkeypatch.setattr(mod, "_load_and_verify_package", lambda: order.append("package") or object())
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
    monkeypatch.setattr(
        mod,
        "_enqueue_read_only_git_status",
        lambda *a, **k: order.append("enqueue") or (object(), "req-1"),
    )
    result = SimpleNamespace(outcome="ok")
    monkeypatch.setattr(
        mod,
        "_wait_for_result",
        lambda *a, **k: order.append("result") or result,
    )
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
    return order, request


def test_transport_is_bracketed_by_one_stable_tunnel_generation(monkeypatch):
    order, request = _install_success(monkeypatch)
    result = mod.qualify_authenticated_agent_transport_with_secure_tunnel(request)
    assert order == [
        "request.validate", "config.validate", "config.runtime", "package", "identity",
        "guest.observe", "service.start", "tunnel.probe", "hello", "heartbeat",
        "guest.observe", "enqueue", "result", "presence", "guest.observe",
        "tunnel.probe", "service.stop", "identity",
    ]
    assert result["status"] == "AUTHENTICATED_AGENT_TRANSPORT_WITH_TUNNEL_QUALIFIED_STOPPED"
    assert result["authenticated_agent_transport_proven"] is True
    assert result["secure_mcp_tunnel_ready_during_transport"] is True
    assert result["tunnel_stable_across_authenticated_transport"] is True
    assert result["full_bridge_command_flow_proven"] is False
    assert result["pairing_ready"] is False


def test_tunnel_generation_drift_fails_closed_and_stops(monkeypatch):
    order, request = _install_success(monkeypatch)
    values = iter([tunnel_evidence(), tunnel_evidence(tunnel_process_id=7777)])
    monkeypatch.setattr(
        mod,
        "qualify_running_secure_mcp_tunnel",
        lambda **k: order.append("tunnel.probe") or next(values),
    )
    with pytest.raises(mod.BridgeCompositeAgentTransportQualificationError, match="tunnel generation changed"):
        mod.qualify_authenticated_agent_transport_with_secure_tunnel(request)
    assert "service.stop" in order


def test_transport_failure_still_stops_before_publication(monkeypatch):
    order, request = _install_success(monkeypatch)
    monkeypatch.setattr(
        mod,
        "_wait_for_result",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("result failed")),
    )
    with pytest.raises(RuntimeError, match="result failed"):
        mod.qualify_authenticated_agent_transport_with_secure_tunnel(request)
    assert order[-1] == "service.stop"


def test_agent_generation_drift_is_rejected(monkeypatch):
    order, request = _install_success(monkeypatch)
    observations = iter([
        {"health_boot_id": "boot-1", "process_id": AGENT_PID},
        {"health_boot_id": "boot-1", "process_id": AGENT_PID},
        {"health_boot_id": "boot-2", "process_id": AGENT_PID},
    ])
    monkeypatch.setattr(
        mod,
        "_observe_guest_agent",
        lambda *a: order.append("guest.observe") or next(observations),
    )
    with pytest.raises(
        mod.BridgeCompositeAgentTransportQualificationError,
        match="process/boot changed across result qualification",
    ):
        mod.qualify_authenticated_agent_transport_with_secure_tunnel(request)
    assert "service.stop" in order
