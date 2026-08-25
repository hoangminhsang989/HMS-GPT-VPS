from __future__ import annotations

import json
from pathlib import Path

import pytest

from hms_gpt_vps.bridge_service_runtime_config import (
    BRIDGE_SERVICE_RUNTIME_SCHEMA_VERSION,
    BridgeServiceRuntimeConfigError,
    parse_bridge_service_runtime_config,
)


_SERVICE_SID = "S-1-5-80-123-456-789-1011-1213"
_VM_ID = "12345678-1234-1234-1234-123456789abc"


def _mapping(tmp_path: Path) -> dict[str, object]:
    runtime_root = tmp_path / "runtime"
    (runtime_root / "secrets").mkdir(parents=True)
    tls_root = tmp_path / "tls-private-key"
    return {
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
        "vm_id": _VM_ID,
        "vm_name": "HMS-VPS-1",
        "trust_root_der_sha256": "c" * 64,
    }


def _bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_config_converts_to_fixed_private_network_authority(tmp_path: Path) -> None:
    config = parse_bridge_service_runtime_config(_bytes(_mapping(tmp_path)))
    runtime = config.to_runtime_config(_SERVICE_SID)

    assert runtime.expected_service_sid == _SERVICE_SID
    assert runtime.tls.firewall.network.switch_name == "HMS-GPT-VPS-Internal"
    assert runtime.tls.firewall.network.subnet == "172.29.240.0/24"
    assert runtime.tls.firewall.network.gateway == "172.29.240.1"
    assert runtime.tls.firewall.network.guest_ipv4 == "172.29.240.10"
    assert runtime.tls.guest.bridge_origin == "https://172.29.240.1:9443"
    assert runtime.secret_storage.root == (
        Path(config.runtime_root) / "secrets" / "service-runtime"
    )


def test_config_rejects_duplicate_json_key(tmp_path: Path) -> None:
    raw = _mapping(tmp_path)
    text = json.dumps(raw, separators=(",", ":"))
    duplicate = (
        '{"schema_version":1,'
        + text[1:]
    ).encode("utf-8")
    with pytest.raises(
        BridgeServiceRuntimeConfigError,
        match="duplicate Bridge runtime config key",
    ):
        parse_bridge_service_runtime_config(duplicate)


def test_config_rejects_unknown_field(tmp_path: Path) -> None:
    raw = _mapping(tmp_path)
    raw["network_override"] = "0.0.0.0/0"
    with pytest.raises(
        BridgeServiceRuntimeConfigError,
        match="unknown=network_override",
    ):
        parse_bridge_service_runtime_config(_bytes(raw))


def test_config_rejects_invalid_pair_ttl_at_parse_boundary(tmp_path: Path) -> None:
    raw = _mapping(tmp_path)
    raw["pair_ttl_seconds"] = 30
    with pytest.raises(ValueError, match="pair_ttl_seconds"):
        parse_bridge_service_runtime_config(_bytes(raw))


def test_config_rejects_noncanonical_sha256(tmp_path: Path) -> None:
    raw = _mapping(tmp_path)
    raw["tls_certificate_der_sha256"] = "B" * 64
    with pytest.raises(
        BridgeServiceRuntimeConfigError,
        match="canonical lowercase SHA-256",
    ):
        parse_bridge_service_runtime_config(_bytes(raw))
