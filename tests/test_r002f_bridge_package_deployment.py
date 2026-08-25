from __future__ import annotations

from pathlib import Path

import pytest

import hms_gpt_vps.bridge_package_deployment as mod
from hms_gpt_vps.bridge_package import build_bridge_package_manifest


SID = "S-1-5-80-1-2-3-4-5"


def _source(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "hms-bridge.exe").write_bytes(b"abc")
    return source, build_bridge_package_manifest(source, version="0.1.0")


def _paths(tmp_path: Path):
    host = tmp_path / "host"
    return (
        host,
        host / "package",
        host / "hms-bridge.manifest.json",
        host / "package" / "hms-bridge.exe",
    )


def test_manifest_bytes_and_sha_are_deterministic(tmp_path: Path):
    _, manifest = _source(tmp_path)
    first = mod.canonical_bridge_package_manifest_bytes(manifest)
    second = mod.canonical_bridge_package_manifest_bytes(manifest)
    assert first == second
    assert first.endswith(b"\n")
    assert len(mod.bridge_package_manifest_sha256(manifest)) == 64


def test_staging_identity_requires_admin_and_absent_service(monkeypatch):
    exact = {
        "elevated_administrator": True,
        "process_sid": "S-1-5-21-1000",
        "identity_name": r"HOST\Admin",
        "service_present": False,
    }
    monkeypatch.setattr(mod, "run_powershell_json", lambda *a, **k: exact)
    assert mod.prove_bridge_package_staging_admin()["service_present"] is False

    monkeypatch.setattr(
        mod,
        "run_powershell_json",
        lambda *a, **k: {**exact, "service_present": True},
    )
    with pytest.raises(mod.BridgePackageDeploymentError, match="must be absent"):
        mod.prove_bridge_package_staging_admin()


def test_acl_script_distinguishes_pre_scm_and_service_read_modes(tmp_path: Path):
    _, manifest = _source(tmp_path)
    pre = mod.build_bridge_package_acl_script(
        Path(r"C:\ProgramData\HMS-GPT-VPS\Bridge.tmp"),
        manifest,
        expected_service_sid=None,
        reconcile=True,
    )
    assert "$serviceAclEnabled = $false" in pre
    assert "SetAccessRuleProtection($true, $false)" in pre
    assert "$rootFiles" in pre

    final = mod.build_bridge_package_acl_script(
        Path(r"C:\ProgramData\HMS-GPT-VPS\Bridge"),
        manifest,
        expected_service_sid=SID,
        reconcile=False,
    )
    assert "$serviceAclEnabled = $true" in final
    assert SID in final
    assert "$reconcile = $false" in final


def test_stage_create_only_publishes_complete_tree_then_removes_marker(
    monkeypatch,
    tmp_path: Path,
):
    source, manifest = _source(tmp_path)
    paths = _paths(tmp_path)
    calls: list[object] = []
    monkeypatch.setattr(mod, "_stage_paths", lambda: paths)
    monkeypatch.setattr(mod, "require_bridge_windows_amd64_pe", lambda path: None)
    monkeypatch.setattr(
        mod,
        "prove_bridge_package_staging_admin",
        lambda: calls.append("admin")
        or {
            "elevated_administrator": True,
            "process_sid": "S-1-5-21-1000",
            "identity_name": r"HOST\Admin",
            "service_present": False,
        },
    )
    monkeypatch.setattr(
        mod,
        "_run_acl",
        lambda host_root, manifest, **kwargs: calls.append(
            ("acl", kwargs["expected_service_sid"], kwargs["reconcile"])
        )
        or {},
    )

    result = mod.stage_bridge_package_create_only(source, manifest)

    host, package, manifest_path, binary = paths
    assert result.created is True
    assert result.service_acl_finalized is False
    assert package.is_dir()
    assert binary.read_bytes() == b"abc"
    assert manifest_path.read_bytes() == mod.canonical_bridge_package_manifest_bytes(
        manifest
    )
    assert not (host / ".hms-bridge-package-stage-owned").exists()
    assert calls == [
        "admin",
        ("acl", None, True),
        ("acl", None, False),
        "admin",
        ("acl", None, False),
    ]


def test_stage_retry_proves_exact_existing_package_without_replacement(
    monkeypatch,
    tmp_path: Path,
):
    source, manifest = _source(tmp_path)
    host, package, manifest_path, binary = _paths(tmp_path)
    package.mkdir(parents=True)
    binary.write_bytes(b"abc")
    manifest_path.write_bytes(mod.canonical_bridge_package_manifest_bytes(manifest))
    monkeypatch.setattr(mod, "_stage_paths", lambda: (host, package, manifest_path, binary))
    monkeypatch.setattr(mod, "require_bridge_windows_amd64_pe", lambda path: None)
    monkeypatch.setattr(
        mod,
        "prove_bridge_package_staging_admin",
        lambda: (_ for _ in ()).throw(AssertionError("must not mutate/prove on retry")),
    )

    result = mod.stage_bridge_package_create_only(source, manifest)

    assert result.created is False
    assert result.binary_sha256 == manifest.sha256


def test_finalize_service_acl_is_sandwiched_by_identity_and_tree_proofs(
    monkeypatch,
    tmp_path: Path,
):
    source, manifest = _source(tmp_path)
    host, package, manifest_path, binary = _paths(tmp_path)
    package.mkdir(parents=True)
    binary.write_bytes(b"abc")
    manifest_path.write_bytes(mod.canonical_bridge_package_manifest_bytes(manifest))
    monkeypatch.setattr(mod, "_stage_paths", lambda: (host, package, manifest_path, binary))
    monkeypatch.setattr(mod, "require_bridge_windows_amd64_pe", lambda path: None)

    calls: list[object] = []
    identity = {
        "service_sid": SID,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
    }
    monkeypatch.setattr(
        mod,
        "prove_hms_bridge_provisioning_identity",
        lambda: calls.append("identity") or identity,
    )
    monkeypatch.setattr(
        mod,
        "_run_acl",
        lambda host_root, manifest, **kwargs: calls.append(
            ("acl", kwargs["expected_service_sid"], kwargs["reconcile"])
        )
        or {},
    )

    result = mod.finalize_bridge_package_service_acl(manifest)

    assert result.service_acl_finalized is True
    assert calls == [
        "identity",
        ("acl", SID, True),
        ("acl", SID, False),
        "identity",
    ]
