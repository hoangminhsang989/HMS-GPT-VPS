from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

import hms_gpt_vps.secure_mcp_tunnel_native_qualification as mod

SID = "S-1-5-80-1-2-3-4-5"
SERVICE_PID = 4242
EXE = Path(r"C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12\tunnel-client-runtime.exe")
SHA = "a" * 64


def evidence(**overrides):
    port = 54321
    attempt = r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-" + "b" * 32
    value = {
        "ready": True,
        "service_name": "HMSBridge",
        "service_sid": SID,
        "service_state": "Running",
        "service_process_id": SERVICE_PID,
        "tunnel_process_id": 5252,
        "tunnel_parent_process_id": SERVICE_PID,
        "tunnel_executable_path": str(PureWindowsPath(str(EXE))),
        "tunnel_executable_sha256": SHA,
        "health_attempt_path": attempt,
        "health_url_path": attempt + r"\health-url.txt",
        "health_base_url": f"http://127.0.0.1:{port}",
        "health_listener_host": "127.0.0.1",
        "health_listener_port": port,
        "readiness_url": f"http://127.0.0.1:{port}/readyz",
        "readiness_status_code": 200,
        "readiness_body_class": "ready",
        "service_stable_after_probe": True,
        "tunnel_stable_after_probe": True,
        "health_listener_stable_after_probe": True,
    }
    value.update(overrides)
    return value


def test_script_proves_independent_child_parent_hash_health_and_approved_ready():
    script = mod._build_native_tunnel_qualification_script(
        service_sid=SID,
        service_process_id=SERVICE_PID,
        executable_path=EXE,
        executable_sha256=SHA,
    )
    assert "ParentProcessId -ne $expectedServicePid" in script
    assert "Get-FileHash" in script
    assert "Expected exactly one tunnel health loopback listener" in script
    assert "Invoke-WebRequest" in script
    assert "mcp initialize requires auth" in script
    assert "startup probe timed out" not in script
    assert "CONTROL_PLANE_API_KEY" not in script
    assert "Get-ExactService" in script and "Get-ExactTunnelProcess" in script


def test_validator_accepts_only_exact_loopback_and_approved_body_class():
    result = mod._validate_native_tunnel_evidence(
        evidence(),
        service_sid=SID,
        service_process_id=SERVICE_PID,
        executable_path=EXE,
        executable_sha256=SHA,
    )
    assert result["tunnel_process_id"] == 5252
    for patch in (
        {"readiness_body_class": "mcp_startup_timeout"},
        {"health_base_url": "http://localhost:54321"},
        {"tunnel_parent_process_id": 9999},
        {"tunnel_process_id": SERVICE_PID},
        {"health_attempt_path": r"C:\Temp\attempt-" + "b" * 32},
    ):
        with pytest.raises(mod.SecureMcpTunnelNativeQualificationError):
            mod._validate_native_tunnel_evidence(
                evidence(**patch),
                service_sid=SID,
                service_process_id=SERVICE_PID,
                executable_path=EXE,
                executable_sha256=SHA,
            )


def test_qualification_brackets_secret_key_package_and_native_probe(monkeypatch):
    calls = []
    package = SimpleNamespace(executable_path=str(EXE), executable_sha256=SHA)

    monkeypatch.setattr(
        mod,
        "prove_bridge_service_secret_storage",
        lambda *a, **k: calls.append("secret-proof") or {"ready": True, "secret_file_acls_exact": True},
    )
    class Store:
        def __init__(self, config): calls.append("store")
        def load(self): calls.append("key-load"); return "same-key"
    monkeypatch.setattr(mod, "TunnelRuntimeApiKeyStore", Store)
    monkeypatch.setattr(
        mod,
        "prove_installed_tunnel_runtime",
        lambda *a, **k: calls.append("package-proof") or package,
    )
    monkeypatch.setattr(
        mod,
        "run_powershell_json",
        lambda *a, **k: calls.append("native-probe") or evidence(),
    )
    result = mod.qualify_running_secure_mcp_tunnel(service_sid=SID, service_process_id=SERVICE_PID)
    assert result["ready"] is True
    assert calls == [
        "secret-proof", "store", "key-load", "package-proof", "native-probe",
        "package-proof", "secret-proof", "key-load",
    ]


def test_qualification_rejects_key_rotation_across_probe(monkeypatch):
    package = SimpleNamespace(executable_path=str(EXE), executable_sha256=SHA)
    keys = iter(["key-one", "key-two"])
    monkeypatch.setattr(mod, "prove_bridge_service_secret_storage", lambda *a, **k: {"ready": True, "secret_file_acls_exact": True})
    class Store:
        def __init__(self, config): pass
        def load(self): return next(keys)
    monkeypatch.setattr(mod, "TunnelRuntimeApiKeyStore", Store)
    monkeypatch.setattr(mod, "prove_installed_tunnel_runtime", lambda *a, **k: package)
    monkeypatch.setattr(mod, "run_powershell_json", lambda *a, **k: evidence())
    with pytest.raises(mod.SecureMcpTunnelNativeQualificationError, match="API-key authority changed"):
        mod.qualify_running_secure_mcp_tunnel(service_sid=SID, service_process_id=SERVICE_PID)
