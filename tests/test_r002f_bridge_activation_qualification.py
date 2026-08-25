from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_activation_qualification as mod
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential

SID = "S-1-5-80-3027300117-82505545-3616633165-1729693371-3881641565"


def _runtime():
    return SimpleNamespace(
        tls=SimpleNamespace(
            firewall=SimpleNamespace(network=SimpleNamespace(gateway="172.29.240.1"), port=9443),
            material=SimpleNamespace(certificate_der_sha256="b" * 64),
            guest=SimpleNamespace(
                vm_id="12345678-1234-1234-1234-123456789abc",
                bridge_origin="https://172.29.240.1:9443",
            ),
        ),
        production=SimpleNamespace(mcp=SimpleNamespace(port=8765)),
    )


def test_request_repr_hides_guest_password_and_trust_root():
    request = mod.BridgeActivationQualificationRequest(
        guest_credential=PowerShellDirectCredential("Admin", "TOP-SECRET-PASSWORD"),
        trust_root_certificate_pem=b"TOP-SECRET-ROOT",
    )
    text = repr(request)
    assert "TOP-SECRET-PASSWORD" not in text
    assert "TOP-SECRET-ROOT" not in text


def test_start_script_requires_exact_owned_tls_and_mcp_listeners():
    script = mod._build_service_start_script(
        service_sid=SID,
        binary_sha256="a" * 64,
        tls_host="172.29.240.1",
        tls_port=9443,
        mcp_port=8765,
    )
    assert "Start-Service" in script
    assert "StartMode -ne 'Manual'" in script
    assert "Get-FileHash" in script
    assert "Get-NetTCPConnection" in script
    assert "OwningProcess" in script
    assert "172.29.240.1" in script
    assert "127.0.0.1" in script
    assert "9443" in script
    assert "8765" in script


def test_stop_script_requires_listener_cleanup_and_keeps_manual():
    script = mod._build_service_stop_script(
        service_sid=SID,
        tls_host="172.29.240.1",
        tls_port=9443,
        mcp_port=8765,
    )
    assert "Stop-Service" in script
    assert "StartMode -ne 'Manual'" in script
    assert "tls_listener_absent" in script
    assert "mcp_listener_absent" in script
    assert "sc.exe config" not in script
    assert "Set-Service" not in script


def test_successful_activation_always_stops_and_keeps_pairing_false(monkeypatch):
    order = []
    runtime = _runtime()
    config = SimpleNamespace(
        validate=lambda: None,
        to_runtime_config=lambda sid: runtime,
    )
    manifest = SimpleNamespace(sha256="a" * 64)
    request = SimpleNamespace(
        validate=lambda: order.append("validate"),
        guest_credential=object(),
        trust_root_certificate_pem=b"ROOT",
    )
    monkeypatch.setattr(mod, "derive_hms_bridge_service_sid", lambda: SID)
    monkeypatch.setattr(mod, "load_protected_bridge_service_runtime_config", lambda: config)
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", SimpleNamespace)
    monkeypatch.setattr(mod, "_load_and_verify_package", lambda: manifest)
    identities = [
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
    ]
    monkeypatch.setattr(mod, "prove_hms_bridge_provisioning_identity", lambda: (order.append("identity"), identities.pop(0))[1])
    monkeypatch.setattr(
        mod,
        "start_hms_bridge_for_qualification",
        lambda *a: (order.append("start"), {"process_id": 4321})[1],
    )
    monkeypatch.setattr(
        mod,
        "qualify_agent_bridge_production_tls",
        lambda *a: (
            order.append("qualify"),
            {
                "live_managed_guest_tls_proven": True,
                "server_certificate_sha256": "b" * 64,
                "vm_id": runtime.tls.guest.vm_id,
                "bridge_origin": runtime.tls.guest.bridge_origin,
            },
        )[1],
    )
    monkeypatch.setattr(
        mod,
        "stop_hms_bridge_after_qualification",
        lambda *a: (order.append("stop"), {"ready": True})[1],
    )

    result = mod.qualify_hms_bridge_activation_probe(request)  # type: ignore[arg-type]
    assert order == ["validate", "identity", "start", "qualify", "stop", "identity"]
    assert result["status"] == "QUALIFIED_STOPPED"
    assert result["service_runtime_ready_proven"] is True
    assert result["live_managed_guest_tls_proven"] is True
    assert result["pairing_ready"] is False
    assert result["authenticated_agent_transport_proven"] is False
    assert result["automatic_start_enabled"] is False


def test_qualification_failure_still_stops_service(monkeypatch):
    order = []
    runtime = _runtime()
    config = SimpleNamespace(validate=lambda: None, to_runtime_config=lambda sid: runtime)
    request = SimpleNamespace(validate=lambda: None, guest_credential=object(), trust_root_certificate_pem=b"ROOT")
    monkeypatch.setattr(mod, "derive_hms_bridge_service_sid", lambda: SID)
    monkeypatch.setattr(mod, "load_protected_bridge_service_runtime_config", lambda: config)
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", SimpleNamespace)
    monkeypatch.setattr(mod, "_load_and_verify_package", lambda: SimpleNamespace(sha256="a" * 64))
    monkeypatch.setattr(mod, "prove_hms_bridge_provisioning_identity", lambda: {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"})
    monkeypatch.setattr(mod, "start_hms_bridge_for_qualification", lambda *a: (order.append("start"), {"process_id": 1})[1])
    monkeypatch.setattr(mod, "qualify_agent_bridge_production_tls", lambda *a: (_ for _ in ()).throw(RuntimeError("probe failed")))
    monkeypatch.setattr(mod, "stop_hms_bridge_after_qualification", lambda *a: (order.append("stop"), {"ready": True})[1])

    with pytest.raises(RuntimeError, match="probe failed"):
        mod.qualify_hms_bridge_activation_probe(request)  # type: ignore[arg-type]
    assert order == ["start", "stop"]
