from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import hms_gpt_vps.r002f_deployment_manifest_authoring as author
from hms_gpt_vps.r002f_deployment_manifest_authoring import (
    ManifestAuthoringResult,
    R002FDeploymentManifestAuthoringError,
    author_reviewed_project_manifest,
    author_runtime_observation_manifest,
)
from hms_gpt_vps.r002f_sealed_execution_manifest import (
    SealedExecutionFile,
    SealedExecutionTreeManifest,
)
from hms_gpt_vps.r002f_sealed_runtime_manifest import (
    ROLE_GIT_RUNTIME,
    ROLE_PYTHON_RUNTIME,
    SealedRuntimeFile,
    SealedRuntimeManifest,
)

COMMIT = "a" * 40
SHA = "b" * 64


def test_result_runtime_requires_external_approval() -> None:
    result = ManifestAuthoringResult(
        manifest_path=r"C:\authority\python.manifest.json",
        manifest_sha256=SHA,
        manifest_role=ROLE_PYTHON_RUNTIME,
        reviewed_commit=None,
        external_approval_required=True,
        external_approval_self_proven=False,
    )
    payload = result.to_dict()
    assert payload["external_approval_required"] is True
    assert payload["external_approval_self_proven"] is False
    assert payload["execution_started"] is False


def test_result_rejects_self_proven_external_approval() -> None:
    with pytest.raises(R002FDeploymentManifestAuthoringError, match="self-prove"):
        ManifestAuthoringResult(
            manifest_path="x",
            manifest_sha256=SHA,
            manifest_role=ROLE_GIT_RUNTIME,
            reviewed_commit=None,
            external_approval_required=True,
            external_approval_self_proven=True,
        ).to_dict()


def test_project_authoring_uses_reviewed_mapping_before_publish(monkeypatch, tmp_path: Path) -> None:
    events: list[str] = []
    manifest = SealedExecutionTreeManifest(
        reviewed_commit=COMMIT,
        tree_role="reviewed-project",
        file_count=1,
        directory_count=0,
        total_size=1,
        files=(
            SealedExecutionFile(
                path="x.txt",
                size=1,
                sha256=hashlib.sha256(b"x").hexdigest(),
                git_blob_sha1=hashlib.sha1(b"blob 1\0x").hexdigest(),
            ),
        ),
    )
    monkeypatch.setattr(author, "canonical_git_sha1", lambda value: value)
    monkeypatch.setattr(author, "canonical_sha256", lambda value, label: value)
    monkeypatch.setattr(
        author,
        "checkout_validation_environment",
        lambda env: {"SAFE": "1"},
    )
    monkeypatch.setattr(
        author,
        "_read_reviewed_git_tree",
        lambda *a, **k: events.append("git-tree") or {"x.txt": manifest.files[0].git_blob_sha1},
    )
    monkeypatch.setattr(
        author,
        "build_reviewed_project_manifest",
        lambda *a, **k: events.append("build") or manifest,
    )
    monkeypatch.setattr(
        author,
        "verify_sealed_execution_tree",
        lambda *a, **k: events.append("verify"),
    )
    published: dict[str, bytes] = {}
    monkeypatch.setattr(
        author,
        "write_bytes_create_only",
        lambda path, data, **k: events.append("write") or published.setdefault(str(path), data),
    )
    monkeypatch.setattr(
        author,
        "read_file_pinned",
        lambda path, **k: published[str(path)],
    )
    checkout_calls: list[str] = []

    result = author_reviewed_project_manifest(
        project_source_root=tmp_path / "export",
        repo_evidence_root=tmp_path / "repo",
        reviewed_commit=COMMIT,
        git_executable=tmp_path / "git.exe",
        git_executable_sha256=SHA,
        output_path=tmp_path / "project.json",
        checkout_validator=lambda *a, **k: checkout_calls.append("checkout"),
        command_runner=lambda *a, **k: None,
    )
    assert checkout_calls == ["checkout", "checkout"]
    assert events == ["git-tree", "build", "verify", "write"]
    assert result.reviewed_commit == COMMIT
    assert result.external_approval_required is False


@pytest.mark.parametrize("role,entrypoint", [
    (ROLE_PYTHON_RUNTIME, "python.exe"),
    (ROLE_GIT_RUNTIME, "git.exe"),
])
def test_runtime_authoring_is_observation_only(monkeypatch, tmp_path: Path, role: str, entrypoint: str) -> None:
    manifest = SealedRuntimeManifest(
        runtime_role=role,
        entrypoint=entrypoint,
        file_count=1,
        directory_count=0,
        total_size=1,
        files=(
            SealedRuntimeFile(
                path=entrypoint,
                size=1,
                sha256=hashlib.sha256(b"x").hexdigest(),
            ),
        ),
    )
    monkeypatch.setattr(author, "build_sealed_runtime_manifest", lambda *a, **k: manifest)
    monkeypatch.setattr(author, "verify_sealed_runtime_tree", lambda *a, **k: None)
    published: dict[str, bytes] = {}
    monkeypatch.setattr(
        author,
        "write_bytes_create_only",
        lambda path, data, **k: published.setdefault(str(path), data),
    )
    monkeypatch.setattr(author, "read_file_pinned", lambda path, **k: published[str(path)])

    result = author_runtime_observation_manifest(
        runtime_source_root=tmp_path / "runtime",
        runtime_role=role,
        entrypoint=entrypoint,
        output_path=tmp_path / f"{role}.json",
    )
    assert result.manifest_sha256 == hashlib.sha256(manifest.to_bytes()).hexdigest()
    assert result.external_approval_required is True
    assert result.external_approval_self_proven is False


def test_runtime_role_must_be_exact(tmp_path: Path) -> None:
    with pytest.raises(R002FDeploymentManifestAuthoringError, match="runtime role"):
        author_runtime_observation_manifest(
            runtime_source_root=tmp_path,
            runtime_role="python",
            entrypoint="python.exe",
            output_path=tmp_path / "x.json",
        )


def test_publish_readback_mismatch_is_rejected(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(author, "write_bytes_create_only", lambda *a, **k: None)
    monkeypatch.setattr(author, "read_file_pinned", lambda *a, **k: b"other")
    with pytest.raises(R002FDeploymentManifestAuthoringError, match="readback"):
        author._publish_manifest(
            tmp_path / "x",
            b"expected",
            max_bytes=1024,
            label="test",
        )
