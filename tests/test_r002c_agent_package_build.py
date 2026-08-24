from __future__ import annotations

import json
from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import (
    AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION,
    WINDOWS_AMD64_MACHINE,
    AgentPackageManifest,
    build_agent_package_manifest,
    load_agent_package_manifest,
    require_windows_amd64_pe,
    verify_agent_package,
    write_agent_package_manifest,
)
from hms_gpt_vps.cli import build_parser


def write_fake_pe(path: Path, *, machine: int = WINDOWS_AMD64_MACHINE) -> None:
    pe_offset = 0x80
    image = bytearray(512)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    image[pe_offset + 4 : pe_offset + 6] = machine.to_bytes(2, "little")
    path.write_bytes(bytes(image))


def test_manifest_round_trip_is_strict_and_reverifies_artifact(tmp_path: Path) -> None:
    artifact = tmp_path / "hms-agent.exe"
    artifact.write_bytes(b"manifest-round-trip")
    manifest = build_agent_package_manifest(artifact, version="0.1.0")
    target = tmp_path / "hms-agent.manifest.json"

    write_agent_package_manifest(target, manifest)
    published = load_agent_package_manifest(target)

    assert published == manifest
    assert published.to_dict()["schema_version"] == AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION
    verify_agent_package(artifact, published)
    raw = json.loads(target.read_text(encoding="utf-8"))
    assert set(raw) == {"schema_version", "filename", "version", "size", "sha256"}


def test_manifest_parser_rejects_unknown_or_wrong_schema_fields() -> None:
    manifest = AgentPackageManifest(
        filename="hms-agent.exe",
        version="0.1.0",
        size=1,
        sha256="a" * 64,
    ).to_dict()

    unknown = dict(manifest)
    unknown["unexpected"] = True
    with pytest.raises(ValueError, match="unknown=unexpected"):
        AgentPackageManifest.from_mapping(unknown)

    wrong_schema = dict(manifest)
    wrong_schema["schema_version"] = 999
    with pytest.raises(ValueError, match="unsupported"):
        AgentPackageManifest.from_mapping(wrong_schema)


def test_windows_amd64_pe_gate_accepts_x64_and_rejects_wrong_machine(tmp_path: Path) -> None:
    x64 = tmp_path / "hms-agent.exe"
    write_fake_pe(x64)
    require_windows_amd64_pe(x64)

    x86 = tmp_path / "wrong.exe"
    write_fake_pe(x86, machine=0x014C)
    with pytest.raises(ValueError, match="Windows AMD64"):
        require_windows_amd64_pe(x86)


def test_windows_amd64_pe_gate_rejects_non_pe_or_out_of_bounds_header(tmp_path: Path) -> None:
    not_pe = tmp_path / "hms-agent.exe"
    not_pe.write_bytes(b"not-a-pe")
    with pytest.raises(ValueError, match="Windows PE"):
        require_windows_amd64_pe(not_pe)

    malformed = tmp_path / "malformed.exe"
    image = bytearray(64)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x1000).to_bytes(4, "little")
    malformed.write_bytes(bytes(image))
    with pytest.raises(ValueError, match="outside artifact bounds"):
        require_windows_amd64_pe(malformed)


def test_cli_exposes_exact_agent_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["--version"])
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "hms-agent 0.1.0"
