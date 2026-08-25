from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import hms_gpt_vps.bridge_tls_material_publication as mod
from hms_gpt_vps.agent_bridge_production_tls import AgentBridgeProductionTlsConfig

SID = "S-1-5-80-1-2-3-4-5"


def _config():
    return AgentBridgeProductionTlsConfig(
        firewall=None,  # type: ignore[arg-type]
        storage=SimpleNamespace(
            storage_root=Path(str(mod.BRIDGE_TLS_PRIVATE_DIR)),
            private_key_path=Path(str(mod.BRIDGE_TLS_PRIVATE_KEY_PATH)),
            private_key_file_sha256="a" * 64,
            bridge_reader_sid=SID,
        ),  # type: ignore[arg-type]
        material=SimpleNamespace(
            certificate_path=Path(str(mod.BRIDGE_TLS_CERTIFICATE_PATH)),
            private_key_path=Path(str(mod.BRIDGE_TLS_PRIVATE_KEY_PATH)),
            certificate_der_sha256="b" * 64,
            private_key_file_sha256="a" * 64,
        ),  # type: ignore[arg-type]
        guest=None,  # type: ignore[arg-type]
    )


def test_fixed_tls_paths_accept_exact_authority():
    mod.require_fixed_bridge_tls_material_paths(_config())


def test_fixed_tls_paths_reject_private_key_override():
    cfg = _config()
    cfg.storage.private_key_path = Path(r"C:\Temp\other.pem")
    try:
        mod.require_fixed_bridge_tls_material_paths(cfg)
    except mod.BridgeTlsMaterialPublicationError as exc:
        assert "storage key path" in str(exc)
    else:
        raise AssertionError("path override was accepted")


def test_prepare_script_contains_no_secret_payload_and_precreates_protected_files():
    stage = PureWindowsPath(str(mod.BRIDGE_TLS_MATERIAL_ROOT) + ".stage-deadbeef")
    script = mod._prepare_script(stage, SID)
    assert "FileMode]::CreateNew" in script
    assert "SetAccessRuleProtection($true, $false)" in script
    assert "FullControl" in script
    assert "private-key" in script
    assert "BEGIN PRIVATE KEY" not in script
    assert "client_secret" not in script


def test_publish_script_uses_atomic_directory_move_and_never_accepts_key_bytes():
    stage = PureWindowsPath(str(mod.BRIDGE_TLS_MATERIAL_ROOT) + ".stage-deadbeef")
    script = mod._publish_script(stage, "c" * 64, "a" * 64, SID)
    assert "[IO.Directory]::Move($stage,$final)" in script
    assert "Get-FileHash" in script
    assert "BEGIN PRIVATE KEY" not in script
    assert "privateKeyPayload" not in script


def test_publication_flow_reproves_identity_and_observer_acl(monkeypatch):
    cfg = _config()
    monkeypatch.setattr(mod, "_validate_inputs", lambda *a: ("b" * 64, "a" * 64))
    identities = [
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
    ]
    monkeypatch.setattr(mod, "prove_hms_bridge_provisioning_identity", lambda: identities.pop(0))
    monkeypatch.setattr(mod, "secrets", SimpleNamespace(token_hex=lambda n: "deadbeef" * 4))

    stage = PureWindowsPath(str(mod.BRIDGE_TLS_MATERIAL_ROOT) + ".stage-" + "deadbeef" * 4)
    stage_cert = stage / "certificate" / "agent-bridge.pem"
    stage_key = stage / "private" / "agent-bridge-private-key.pem"
    calls = []
    responses = [
        {
            "ready": True,
            "stage_root": str(stage),
            "certificate_path": str(stage_cert),
            "private_key_path": str(stage_key),
            "service_sid": SID,
        },
        {
            "ready": True,
            "published": True,
            "final_root": str(mod.BRIDGE_TLS_MATERIAL_ROOT),
            "certificate_path": str(mod.BRIDGE_TLS_CERTIFICATE_PATH),
            "private_key_path": str(mod.BRIDGE_TLS_PRIVATE_KEY_PATH),
            "certificate_file_sha256": __import__("hashlib").sha256(b"CERT").hexdigest(),
            "private_key_file_sha256": "a" * 64,
            "service_sid": SID,
        },
    ]
    monkeypatch.setattr(mod, "run_powershell_json", lambda script, timeout_seconds: (calls.append(script), responses.pop(0))[1])
    writes = []
    monkeypatch.setattr(mod, "_write_precreated", lambda path, data, label: writes.append((str(path), data, label)))
    fake_loaded = SimpleNamespace(validate=lambda: None)
    monkeypatch.setattr(mod, "load_agent_bridge_tls_material", lambda config: fake_loaded)
    acl = [
        {"ready": True, "changed": True},
        {"ready": True, "changed": False},
    ]
    monkeypatch.setattr(mod, "ensure_agent_bridge_private_key_storage", lambda config: acl.pop(0))

    result = mod.publish_bridge_tls_material_create_only(cfg, b"CERT", b"KEY")
    assert result["ready"] is True
    assert result["runtime_listener_started"] is False
    assert result["pairing_ready"] is False
    assert len(writes) == 2
    assert writes[1][1] == b"KEY"
    assert len(calls) == 2
    assert identities == []
