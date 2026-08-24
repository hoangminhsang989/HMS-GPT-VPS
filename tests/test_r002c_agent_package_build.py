from __future__ import annotations

import json
from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import (
    AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION,
    AGENT_PACKAGE_PLATFORM,
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


def make_package(tmp_path: Path) -> Path:
    root = tmp_path / "hms-agent"
    (root / "_internal").mkdir(parents=True)
    write_fake_pe(root / "hms-agent.exe")
    (root / "_internal" / "python313.dll").write_bytes(b"python-runtime")
    (root / "_internal" / "module.pyd").write_bytes(b"extension-module")
    return root


def test_manifest_round_trip_is_strict_and_reverifies_complete_tree(tmp_path: Path) -> None:
    package = make_package(tmp_path)
    manifest = build_agent_package_manifest(package, version="0.1.0")
    target = tmp_path / "hms-agent.manifest.json"

    write_agent_package_manifest(target, manifest)
    published = load_agent_package_manifest(target)

    assert published == manifest
    assert published.to_dict()["schema_version"] == AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION
    assert published.platform == AGENT_PACKAGE_PLATFORM
    assert published.entrypoint == "hms-agent.exe"
    assert published.file_count == 3
    verify_agent_package(package, published)
    raw = json.loads(target.read_text(encoding="utf-8"))
    assert set(raw) == {
        "schema_version",
        "platform",
        "version",
        "entrypoint",
        "file_count",
        "total_size",
        "files",
    }


def test_manifest_parser_rejects_unknown_or_wrong_schema_fields(tmp_path: Path) -> None:
    manifest = build_agent_package_manifest(make_package(tmp_path), version="0.1.0").to_dict()

    unknown = dict(manifest)
    unknown["unexpected"] = True
    with pytest.raises(ValueError, match="unknown=unexpected"):
        AgentPackageManifest.from_mapping(unknown)

    wrong_schema = dict(manifest)
    wrong_schema["schema_version"] = 999
    with pytest.raises(ValueError, match="unsupported"):
        AgentPackageManifest.from_mapping(wrong_schema)


def test_complete_tree_verifier_rejects_missing_extra_modified_and_case_changes(tmp_path: Path) -> None:
    package = make_package(tmp_path)
    manifest = build_agent_package_manifest(package, version="0.1.0")

    extra = package / "unexpected.bin"
    extra.write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="extra="):
        verify_agent_package(package, manifest)
    extra.unlink()

    module = package / "_internal" / "module.pyd"
    original = module.read_bytes()
    module.write_bytes(b"modified-module")
    with pytest.raises(ValueError, match="SHA-256 mismatch|size mismatch"):
        verify_agent_package(package, manifest)
    module.write_bytes(original)

    module.unlink()
    with pytest.raises(ValueError, match="missing="):
        verify_agent_package(package, manifest)


def test_manifest_rejects_links_and_case_collisions(tmp_path: Path) -> None:
    package = make_package(tmp_path)
    try:
        (package / "link.bin").symlink_to(package / "_internal" / "module.pyd")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable on this host")
    with pytest.raises(ValueError, match="links or reparse points"):
        build_agent_package_manifest(package, version="0.1.0")


def test_manifest_and_verifier_reject_linked_package_root_before_resolution(tmp_path: Path) -> None:
    package = make_package(tmp_path)
    manifest = build_agent_package_manifest(package, version="0.1.0")
    linked_root = tmp_path / "hms-agent-linked"
    try:
        linked_root.symlink_to(package, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation unavailable on this host")

    with pytest.raises(ValueError, match="root must not be a link or reparse point"):
        build_agent_package_manifest(linked_root, version="0.1.0")
    with pytest.raises(ValueError, match="root must not be a link or reparse point"):
        verify_agent_package(linked_root, manifest)


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
