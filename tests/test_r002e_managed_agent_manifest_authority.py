from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hms_gpt_vps.agent_package import (
    MAX_AGENT_MANIFEST_BYTES,
    AgentPackageFile,
    AgentPackageManifest,
)
from hms_gpt_vps.agent_package_manifest_artifact import (
    canonical_agent_package_manifest_bytes,
)
from hms_gpt_vps.managed_agent_provisioning_runtime import (
    ManagedAgentProvisioningError,
    ManagedAgentProvisioningRuntime,
    _load_agent_package_manifest_pinned,
    _manifest_target_matches_opened_file,
)


def _package_and_manifest(tmp_path: Path) -> tuple[Path, Path, AgentPackageManifest]:
    package = tmp_path / "hms-agent"
    package.mkdir()
    entrypoint = package / "hms-agent.exe"
    payload = b"entrypoint"
    entrypoint.write_bytes(payload)
    manifest = AgentPackageManifest(
        platform="windows-x64",
        version="0.1.0",
        entrypoint="hms-agent.exe",
        file_count=1,
        total_size=len(payload),
        files=(
            AgentPackageFile(
                path="hms-agent.exe",
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ),
        ),
    )
    manifest.validate()
    manifest_path = tmp_path / "hms-agent.manifest.json"
    manifest_path.write_bytes(canonical_agent_package_manifest_bytes(manifest))
    return package, manifest_path, manifest


def test_pinned_manifest_loader_returns_exact_canonical_bytes(tmp_path: Path) -> None:
    _, manifest_path, expected = _package_and_manifest(tmp_path)
    manifest, data = _load_agent_package_manifest_pinned(manifest_path)
    assert manifest == expected
    assert data == canonical_agent_package_manifest_bytes(expected)


def test_runtime_manifest_authority_does_not_reopen_with_path_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, manifest_path, expected = _package_and_manifest(tmp_path)
    runtime = object.__new__(ManagedAgentProvisioningRuntime)
    runtime.config = SimpleNamespace(
        package_source_root=package,
        package_manifest_path=manifest_path,
    )

    def _forbid_read_bytes(self: Path) -> bytes:
        raise AssertionError("approved manifest authority must use pinned opened bytes")

    monkeypatch.setattr(Path, "read_bytes", _forbid_read_bytes)
    assert runtime._load_approved_manifest() == expected


def test_runtime_manifest_authority_rejects_noncanonical_bytes(tmp_path: Path) -> None:
    package, manifest_path, manifest = _package_and_manifest(tmp_path)
    manifest_path.write_text(
        json.dumps(manifest.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    runtime = object.__new__(ManagedAgentProvisioningRuntime)
    runtime.config = SimpleNamespace(
        package_source_root=package,
        package_manifest_path=manifest_path,
    )
    with pytest.raises(ManagedAgentProvisioningError, match="not canonical"):
        runtime._load_approved_manifest()


def test_pinned_manifest_loader_rejects_symlinked_manifest(tmp_path: Path) -> None:
    _, manifest_path, _ = _package_and_manifest(tmp_path)
    linked = tmp_path / "linked.manifest.json"
    try:
        linked.symlink_to(manifest_path)
    except OSError:
        pytest.skip("host does not permit creating file symlinks")
    with pytest.raises(ManagedAgentProvisioningError, match="link or reparse"):
        _load_agent_package_manifest_pinned(linked)


def test_pinned_manifest_loader_rejects_symlinked_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    package = real_parent / "hms-agent"
    package.mkdir()
    payload = b"entrypoint"
    (package / "hms-agent.exe").write_bytes(payload)
    manifest = AgentPackageManifest(
        platform="windows-x64",
        version="0.1.0",
        entrypoint="hms-agent.exe",
        file_count=1,
        total_size=len(payload),
        files=(
            AgentPackageFile(
                path="hms-agent.exe",
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ),
        ),
    )
    manifest_path = real_parent / "hms-agent.manifest.json"
    manifest_path.write_bytes(canonical_agent_package_manifest_bytes(manifest))
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit creating directory symlinks")
    with pytest.raises(ManagedAgentProvisioningError, match="link or reparse"):
        _load_agent_package_manifest_pinned(linked_parent / manifest_path.name)


def test_pinned_manifest_loader_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "oversized.manifest.json"
    path.write_bytes(b"x" * (MAX_AGENT_MANIFEST_BYTES + 1))
    with pytest.raises(ManagedAgentProvisioningError, match="size"):
        _load_agent_package_manifest_pinned(path)


def test_manifest_identity_check_rejects_path_replacement(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_bytes(b"owned")
    opened_stat = path.stat()
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b"replacement")
    replacement.replace(path)
    assert not _manifest_target_matches_opened_file(path, opened_stat)
