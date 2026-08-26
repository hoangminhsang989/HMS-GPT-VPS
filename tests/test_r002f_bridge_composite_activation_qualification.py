from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_composite_activation_qualification as mod

SID = "S-1-5-80-1-2-3-4-5"
SERVICE_PID = 4242
TUNNEL_PID = 5252
VM_ID = "12345678-1234-1234-1234-123456789abc"


class Request:
    def __init__(self, order):
        self.order = order
        self.guest_credential = object()
        self.trust_root_certificate_pem = b"ROOT"

    def validate(self):
        self.order.append("request.validate")


class Config:
    def __init__(self, order):
        self.order = order
        self.runtime = SimpleNamespace(
            tls=SimpleNamespace(
                material=SimpleNamespace(certificate_der_sha256="b" * 64),
                guest=SimpleNamespace(
                    vm_id=VM_ID,
                    bridge_origin="https://172.29.240.1:9443",
                ),
            )
        )

    def validate(self):
        self.order.append("config.validate")

    def to_runtime_config(self, sid):
        assert sid == SID
        self.order.append("config.runtime")
        return self.runtime


def tunnel_evidence(**overrides):
    value = {
        "ready": True,
        "service_process_id": SERVICE_PID,
        "tunnel_process_id": TUNNEL_PID,
        "tunnel_parent_process_id": SERVICE_PID,
        "tunnel_executable_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12\tunnel-client-runtime.exe",
        "tunnel_executable_sha256": "a" * 64,
        "health_attempt_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-" + "c" * 32,
        "health_url_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-" + "c" * 32 + r"\health-url.txt",
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
    identities = iter(
        [
            {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
            {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
        ]
    )
    monkeypatch.setattr(mod, "BridgeActivationQualificationRequest", Request)
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", Config)
    monkeypatch.setattr(mod, "derive_hms_bridge_service_sid", lambda: SID)
    monkeypatch.setattr(mod, "load_protected_bridge_service_runtime_config", lambda: config)
    monkeypatch.setattr(mod, "_load_and_verify_package", lambda: order.append("package") or object())
    monkeypatch.setattr(
        mod,
        "prove_hms_bridge_provisioning_identity",
        lambda: order.append("identity") or next(identities),
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
    monkeypatch.setattr(
        mod,
        "qualify_agent_bridge_production_tls",
        lambda *a: order.append("guest.tls") or {
            "live_managed_guest_tls_proven": True,
            "server_certificate_sha256": "b" * 64,
            "vm_id": VM_ID,
            "bridge_origin": "https://172.29.240.1:9443",
        },
    )
    monkeypatch.setattr(
        mod,
        "stop_hms_bridge_after_qualification",
        lambda *a: order.append("service.stop") or {"ready": True},
    )
    return order, request


def test_composite_probe_brackets_managed_guest_tls_with_same_tunnel_generation(monkeypatch):
    order, request = _install_success(monkeypatch)
    result = mod.qualify_hms_bridge_composite_activation_probe(request)
    assert order == [
        "request.validate",
        "config.validate",
        "config.runtime",
        "package",
        "identity",
        "service.start",
        "tunnel.probe",
        "guest.tls",
        "tunnel.probe",
        "service.stop",
        "identity",
    ]
    assert result["status"] == "QUALIFIED_STOPPED"
    assert result["runtime_process_id"] == SERVICE_PID
    assert result["tunnel_process_id"] == TUNNEL_PID
    assert result["secure_mcp_tunnel_ready_during_probe"] is True
    assert result["tunnel_stable_across_managed_guest_probe"] is True
    assert result["pairing_ready"] is False
    assert result["full_bridge_command_flow_proven"] is False


def test_tunnel_generation_drift_fails_closed_and_still_stops(monkeypatch):
    order, request = _install_success(monkeypatch)
    values = iter([tunnel_evidence(), tunnel_evidence(tunnel_process_id=6262)])
    monkeypatch.setattr(
        mod,
        "qualify_running_secure_mcp_tunnel",
        lambda **k: order.append("tunnel.probe") or next(values),
    )
    with pytest.raises(
        mod.BridgeCompositeActivationQualificationError,
        match="tunnel generation changed",
    ):
        mod.qualify_hms_bridge_composite_activation_probe(request)
    assert "service.stop" in order


def test_tunnel_probe_failure_fails_closed_and_still_stops(monkeypatch):
    order, request = _install_success(monkeypatch)
    def fail(**kwargs):
        order.append("tunnel.probe")
        raise RuntimeError("native tunnel proof failed")
    monkeypatch.setattr(mod, "qualify_running_secure_mcp_tunnel", fail)
    with pytest.raises(RuntimeError, match="native tunnel proof failed"):
        mod.qualify_hms_bridge_composite_activation_probe(request)
    assert order[-1] == "service.stop"


def test_managed_guest_vm_identity_drift_is_rejected(monkeypatch):
    order, request = _install_success(monkeypatch)
    monkeypatch.setattr(
        mod,
        "qualify_agent_bridge_production_tls",
        lambda *a: order.append("guest.tls") or {
            "live_managed_guest_tls_proven": True,
            "server_certificate_sha256": "b" * 64,
            "vm_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bridge_origin": "https://172.29.240.1:9443",
        },
    )
    with pytest.raises(
        mod.BridgeCompositeActivationQualificationError,
        match="VMId differs",
    ):
        mod.qualify_hms_bridge_composite_activation_probe(request)
    assert "service.stop" in order
