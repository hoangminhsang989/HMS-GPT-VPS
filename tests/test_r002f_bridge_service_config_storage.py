from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import hms_gpt_vps.bridge_service_config_storage as storage_module
import hms_gpt_vps.bridge_service_runtime_config as config_module
from hms_gpt_vps.bridge_service_config_storage import (
    DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
    BridgeServiceConfigStorageError,
    build_bridge_service_config_storage_script,
    load_protected_bridge_service_runtime_config,
)


def test_storage_authority_rejects_nonfixed_config_path(tmp_path: Path) -> None:
    with pytest.raises(
        BridgeServiceConfigStorageError,
        match="fixed ProgramData authority",
    ):
        build_bridge_service_config_storage_script(
            tmp_path / "bridge-runtime.json",
            reconcile=False,
        )


def test_read_only_storage_script_pins_exact_service_acl_shape() -> None:
    script = build_bridge_service_config_storage_script(
        DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
        reconcile=False,
    )
    assert "$reconcile = $false" in script
    assert r"NT SERVICE\HMSBridge" in script
    assert "ReadAndExecute" in script
    assert "FileSystemRights]::Read" in script
    assert "FileSystemRights]::Synchronize" in script
    assert "SetAccessRuleProtection($true, $false)" in script


def test_protected_loader_sandwiches_exact_bytes_between_acl_proofs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'{"schema_version":1}'
    digest = hashlib.sha256(payload).hexdigest()
    events: list[str] = []
    sentinel = object()

    def prove(path):
        events.append("proof")
        return {"config_sha256": digest}

    monkeypatch.setattr(
        storage_module,
        "prove_bridge_service_runtime_config_storage",
        prove,
    )
    monkeypatch.setattr(
        storage_module,
        "read_file_pinned",
        lambda path, max_bytes, label: events.append("read") or payload,
    )
    monkeypatch.setattr(
        config_module,
        "parse_bridge_service_runtime_config",
        lambda data: events.append("parse") or sentinel,
    )

    assert (
        load_protected_bridge_service_runtime_config(
            DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH
        )
        is sentinel
    )
    assert events == ["proof", "read", "parse", "proof"]


def test_protected_loader_rejects_bytes_different_from_acl_pinned_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"different"
    monkeypatch.setattr(
        storage_module,
        "prove_bridge_service_runtime_config_storage",
        lambda path: {"config_sha256": "a" * 64},
    )
    monkeypatch.setattr(
        storage_module,
        "read_file_pinned",
        lambda path, max_bytes, label: payload,
    )
    monkeypatch.setattr(
        config_module,
        "parse_bridge_service_runtime_config",
        lambda data: pytest.fail("mismatched bytes must fail before parse"),
    )

    with pytest.raises(
        BridgeServiceConfigStorageError,
        match="pre-read identity",
    ):
        load_protected_bridge_service_runtime_config(
            DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH
        )
