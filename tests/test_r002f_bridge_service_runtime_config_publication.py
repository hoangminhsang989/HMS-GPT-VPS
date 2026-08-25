from __future__ import annotations

import json
from pathlib import Path, PureWindowsPath

import pytest

import hms_gpt_vps.bridge_service_runtime_config_publication as mod
from hms_gpt_vps.bridge_service_runtime_config import (
    BRIDGE_SERVICE_RUNTIME_SCHEMA_VERSION,
    DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
    parse_bridge_service_runtime_config,
)


SID = "S-1-5-80-123-456-789-1011-1213"
VM_ID = "12345678-1234-1234-1234-123456789abc"


def _config(tmp_path: Path):
    runtime_root = tmp_path / "runtime"
    (runtime_root / "secrets").mkdir(parents=True)
    tls_root = tmp_path / "tls-private-key"
    raw = {
        "schema_version": BRIDGE_SERVICE_RUNTIME_SCHEMA_VERSION,
        "instance_id": "HMS-VPS-1",
        "runtime_root": str(runtime_root),
        "provision_state_path": str(runtime_root / "provision-state.json"),
        "bridge_base_url": "https://bridge.example.test",
        "mcp_issuer_url": "https://issuer.example.test",
        "mcp_resource_server_url": "https://resource.example.test",
        "mcp_port": 8765,
        "presence_max_age_seconds": 90,
        "pair_ttl_seconds": 300,
        "tls_certificate_path": str(tmp_path / "agent-bridge.pem"),
        "tls_private_key_path": str(tls_root / "agent-bridge-private-key.pem"),
        "tls_storage_root": str(tls_root),
        "tls_certificate_der_sha256": "b" * 64,
        "tls_private_key_file_sha256": "a" * 64,
        "tls_port": 9443,
        "vm_id": VM_ID,
        "vm_name": "HMS-VPS-1",
        "trust_root_der_sha256": "c" * 64,
    }
    return parse_bridge_service_runtime_config(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _identity():
    return {
        "elevated_administrator": True,
        "process_sid": "S-1-5-21-1000",
        "identity_name": r"HOST\Admin",
        "service_name": "HMSBridge",
        "service_start_name": r"NT SERVICE\HMSBridge",
        "service_start_mode": "Manual",
        "service_state": "Stopped",
        "service_sid": SID,
    }


def test_canonical_bytes_are_deterministic_and_round_trip(tmp_path: Path):
    config = _config(tmp_path)
    first = mod.canonical_bridge_service_runtime_config_bytes(config)
    second = mod.canonical_bridge_service_runtime_config_bytes(config)
    assert first == second
    assert parse_bridge_service_runtime_config(first) == config
    assert len(mod.bridge_service_runtime_config_sha256(config)) == 64


def test_publication_script_is_create_only_and_acl_pinned(tmp_path: Path):
    config = _config(tmp_path)
    script = mod.build_bridge_service_runtime_config_publication_script(
        config,
        expected_service_sid=SID,
    )
    assert "[System.IO.FileMode]::CreateNew" in script
    assert "[System.IO.File]::Move" in script
    assert "publication is create-only" in script
    assert "SetAccessRuleProtection($true, $false)" in script
    assert "HMSBridge must remain Stopped" in script
    assert "File]::Replace" not in script


def test_publication_rejects_path_override(tmp_path: Path):
    config = _config(tmp_path)
    with pytest.raises(
        mod.BridgeServiceRuntimeConfigPublicationError,
        match="fixed authority",
    ):
        mod.build_bridge_service_runtime_config_publication_script(
            config,
            expected_service_sid=SID,
            path=tmp_path / "other.json",
        )


def test_publish_orders_identity_publish_proofs_and_reload(
    monkeypatch,
    tmp_path: Path,
):
    config = _config(tmp_path)
    expected_sha = mod.bridge_service_runtime_config_sha256(config)
    calls: list[str] = []

    monkeypatch.setattr(
        mod,
        "prove_hms_bridge_provisioning_identity",
        lambda: calls.append("identity") or _identity(),
    )
    monkeypatch.setattr(
        mod,
        "run_powershell_json",
        lambda *a, **k: calls.append("publish")
        or {
            "ready": True,
            "created": True,
            "config_path": str(PureWindowsPath(str(DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH))),
            "config_sha256": expected_sha,
            "service_sid": SID,
            "service_state": "Stopped",
            "service_start_mode": "Manual",
            "root_acl_exact": True,
            "config_acl_exact": True,
            "config_reparse_point": False,
        },
    )
    monkeypatch.setattr(
        mod,
        "prove_bridge_service_runtime_config_storage",
        lambda path: calls.append("storage")
        or {"changed": False, "config_sha256": expected_sha},
    )
    monkeypatch.setattr(
        mod,
        "load_protected_bridge_service_runtime_config",
        lambda path: calls.append("load") or config,
    )

    result = mod.publish_bridge_service_runtime_config_create_only(config)

    assert calls == ["identity", "publish", "storage", "load", "identity"]
    assert result["created"] is True
    assert result["protected_load_proven"] is True
    assert result["post_identity_proven"] is True


def test_publish_rejects_storage_sha_drift(monkeypatch, tmp_path: Path):
    config = _config(tmp_path)
    expected_sha = mod.bridge_service_runtime_config_sha256(config)
    monkeypatch.setattr(
        mod,
        "prove_hms_bridge_provisioning_identity",
        lambda: _identity(),
    )
    monkeypatch.setattr(
        mod,
        "run_powershell_json",
        lambda *a, **k: {
            "ready": True,
            "created": True,
            "config_path": str(PureWindowsPath(str(DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH))),
            "config_sha256": expected_sha,
            "service_sid": SID,
            "service_state": "Stopped",
            "service_start_mode": "Manual",
            "root_acl_exact": True,
            "config_acl_exact": True,
            "config_reparse_point": False,
        },
    )
    monkeypatch.setattr(
        mod,
        "prove_bridge_service_runtime_config_storage",
        lambda path: {"changed": False, "config_sha256": "0" * 64},
    )
    with pytest.raises(
        mod.BridgeServiceRuntimeConfigPublicationError,
        match="storage SHA-256 differs",
    ):
        mod.publish_bridge_service_runtime_config_create_only(config)
