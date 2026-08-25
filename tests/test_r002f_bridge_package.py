from __future__ import annotations

import json
from pathlib import Path

import pytest

import hms_gpt_vps.bridge_package as mod


def write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_build_and_verify_complete_bridge_tree(tmp_path):
    root = tmp_path / "hms-bridge"
    write_file(root / "hms-bridge.exe", b"MZ-not-a-real-pe")
    write_file(root / "_internal" / "runtime.bin", b"runtime")
    manifest = mod.build_bridge_package_manifest(root, version="0.1.0")
    assert manifest.entrypoint == "hms-bridge.exe"
    assert manifest.file_count == 2
    mod.verify_bridge_package(root, manifest)


def test_verify_rejects_tree_drift(tmp_path):
    root = tmp_path / "hms-bridge"
    write_file(root / "hms-bridge.exe", b"bridge")
    manifest = mod.build_bridge_package_manifest(root, version="0.1.0")
    write_file(root / "extra.dll", b"unexpected")
    with pytest.raises(ValueError, match="tree differs"):
        mod.verify_bridge_package(root, manifest)


def test_manifest_round_trip_is_exact(tmp_path):
    root = tmp_path / "hms-bridge"
    write_file(root / "hms-bridge.exe", b"bridge")
    manifest = mod.build_bridge_package_manifest(root, version="0.1.0")
    path = tmp_path / "manifest.json"
    mod.write_bridge_package_manifest(path, manifest)
    loaded = mod.load_bridge_package_manifest(path)
    assert loaded == manifest
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["schema_version"] == mod.BRIDGE_PACKAGE_MANIFEST_SCHEMA_VERSION
    assert raw["platform"] == "windows-x64"


def test_manifest_rejects_agent_entrypoint(tmp_path):
    root = tmp_path / "hms-bridge"
    write_file(root / "hms-bridge.exe", b"bridge")
    manifest = mod.build_bridge_package_manifest(root, version="0.1.0")
    raw = manifest.to_dict()
    raw["entrypoint"] = "hms-agent.exe"
    with pytest.raises(ValueError, match="hms-bridge.exe"):
        mod.BridgePackageManifest.from_mapping(raw)


def test_pe_gate_requires_bridge_filename(tmp_path):
    path = tmp_path / "other.exe"
    write_file(path, b"MZ")
    with pytest.raises(ValueError, match="hms-bridge.exe"):
        mod.require_bridge_windows_amd64_pe(path)


def test_load_manifest_rejects_duplicate_fields(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(
        '{"schema_version":2,"schema_version":2,"platform":"windows-x64",'
        '"version":"0.1.0","entrypoint":"hms-bridge.exe","file_count":1,'
        '"total_size":1,"files":[{"path":"hms-bridge.exe","size":1,'
        '"sha256":"' + ("0" * 64) + '"}]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate fields"):
        mod.load_bridge_package_manifest(path)
