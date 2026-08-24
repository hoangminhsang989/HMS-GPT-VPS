from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def test_attestation_preserves_package_root_link_evidence_until_verifier() -> None:
    source = _source("scripts/attest_agent_package.py")

    assert "package_root = args.package_root\n" in source
    assert "package_root = args.package_root.resolve" not in source
    assert "manifest = build_agent_package_manifest(package_root" in source


def test_native_start_probe_preserves_package_root_link_evidence_until_verifier() -> None:
    source = _source("scripts/probe_native_agent_service_start.py")

    assert 'source_package = artifact_root / "hms-agent"' in source
    assert '(artifact_root / "hms-agent").resolve' not in source
    assert "verify_agent_package(source_package, manifest)" in source


def test_native_qualification_preserves_package_root_link_evidence_until_verifier() -> None:
    source = _source("scripts/qualify_native_agent_service.py")

    assert 'source_package = package_dir / "hms-agent"' in source
    assert '(package_dir / "hms-agent").resolve' not in source
    assert "verify_agent_package(source_package, manifest)" in source
