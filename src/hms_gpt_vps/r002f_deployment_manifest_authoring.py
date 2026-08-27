from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess
from typing import Callable, Mapping

from .external_mcp_command_flow_contract import canonical_git_sha1
from .qualification_file_authority import read_file_pinned, write_bytes_create_only
from .r002f_reviewed_checkout_authority import require_reviewed_clean_checkout
from .r002f_reviewed_git_environment import checkout_validation_environment
from .r002f_reviewed_git_tree_authority import _read_reviewed_git_tree
from .r002f_reviewed_toolchain_authority import canonical_sha256
from .r002f_sealed_execution_manifest import (
    MAX_MANIFEST_BYTES as MAX_PROJECT_MANIFEST_BYTES,
    build_reviewed_project_manifest,
    verify_sealed_execution_tree,
)
from .r002f_sealed_runtime_manifest import (
    MAX_MANIFEST_BYTES as MAX_RUNTIME_MANIFEST_BYTES,
    ROLE_GIT_RUNTIME,
    ROLE_PYTHON_RUNTIME,
    build_sealed_runtime_manifest,
    verify_sealed_runtime_tree,
)

_MAX_RESULT_TEXT = 4096


class R002FDeploymentManifestAuthoringError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManifestAuthoringResult:
    manifest_path: str
    manifest_sha256: str
    manifest_role: str
    reviewed_commit: str | None
    external_approval_required: bool
    external_approval_self_proven: bool

    def to_dict(self) -> dict[str, object]:
        if (
            not isinstance(self.manifest_path, str)
            or not self.manifest_path
            or len(self.manifest_path) > _MAX_RESULT_TEXT
        ):
            raise R002FDeploymentManifestAuthoringError("manifest path is invalid")
        canonical_sha256(self.manifest_sha256, "manifest SHA-256")
        if self.manifest_role not in {
            "reviewed-project",
            ROLE_PYTHON_RUNTIME,
            ROLE_GIT_RUNTIME,
        }:
            raise R002FDeploymentManifestAuthoringError("manifest role is invalid")
        if self.reviewed_commit is not None:
            canonical_git_sha1(self.reviewed_commit)
        if type(self.external_approval_required) is not bool:
            raise R002FDeploymentManifestAuthoringError(
                "external_approval_required must be exact bool"
            )
        if type(self.external_approval_self_proven) is not bool:
            raise R002FDeploymentManifestAuthoringError(
                "external_approval_self_proven must be exact bool"
            )
        if self.external_approval_self_proven:
            raise R002FDeploymentManifestAuthoringError(
                "authoring process cannot self-prove external approval"
            )
        return {
            "schema_version": 1,
            "qualification": "R002F_DEPLOYMENT_MANIFEST_AUTHORING",
            "status": "MANIFEST_CREATE_ONLY_PUBLISHED",
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_sha256,
            "manifest_role": self.manifest_role,
            "reviewed_commit": self.reviewed_commit,
            "external_approval_required": self.external_approval_required,
            "external_approval_self_proven": self.external_approval_self_proven,
            "execution_started": False,
            "hyperv_mutated": False,
            "bridge_started": False,
            "tunnel_started": False,
        }


def _publish_manifest(
    output_path: Path,
    data: bytes,
    *,
    max_bytes: int,
    label: str,
) -> str:
    write_bytes_create_only(
        output_path,
        data,
        max_bytes=max_bytes,
        label=label,
    )
    readback = read_file_pinned(
        output_path,
        max_bytes=max_bytes,
        label=label,
    )
    if readback != data:
        raise R002FDeploymentManifestAuthoringError(
            f"{label} readback differs from canonical bytes"
        )
    return hashlib.sha256(readback).hexdigest()


def author_reviewed_project_manifest(
    *,
    project_source_root: Path,
    repo_evidence_root: Path,
    reviewed_commit: str,
    git_executable: Path,
    git_executable_sha256: str,
    output_path: Path,
    environment: Mapping[str, str] | None = None,
    checkout_validator: Callable[..., None] = require_reviewed_clean_checkout,
    command_runner: Callable[..., object] = subprocess.run,
) -> ManifestAuthoringResult:
    """Create a project manifest only from an independently reviewed Git tree."""

    expected = canonical_git_sha1(reviewed_commit)
    git_sha = canonical_sha256(
        git_executable_sha256,
        "reviewed Git executable SHA-256",
    )
    if not isinstance(project_source_root, Path):
        raise TypeError("project_source_root must be pathlib.Path")
    if not isinstance(repo_evidence_root, Path):
        raise TypeError("repo_evidence_root must be pathlib.Path")
    if not isinstance(git_executable, Path):
        raise TypeError("git_executable must be pathlib.Path")
    if not isinstance(output_path, Path):
        raise TypeError("output_path must be pathlib.Path")

    source_environment = os.environ if environment is None else environment
    safe_environment = checkout_validation_environment(source_environment)
    repo = repo_evidence_root.expanduser().absolute()
    git_path = git_executable.expanduser().absolute()

    checkout_validator(
        repo,
        expected,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=safe_environment,
        command_runner=command_runner,
    )
    reviewed_tree = _read_reviewed_git_tree(
        repo,
        expected,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=safe_environment,
        command_runner=command_runner,
    )
    checkout_validator(
        repo,
        expected,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=safe_environment,
        command_runner=command_runner,
    )

    manifest = build_reviewed_project_manifest(
        project_source_root.expanduser().absolute(),
        reviewed_commit=expected,
        expected_git_blobs=reviewed_tree,
    )
    verify_sealed_execution_tree(
        project_source_root.expanduser().absolute(),
        manifest,
    )
    data = manifest.to_bytes()
    digest = _publish_manifest(
        output_path.expanduser().absolute(),
        data,
        max_bytes=MAX_PROJECT_MANIFEST_BYTES,
        label="R002F reviewed project manifest",
    )
    return ManifestAuthoringResult(
        manifest_path=str(output_path.expanduser().absolute()),
        manifest_sha256=digest,
        manifest_role="reviewed-project",
        reviewed_commit=expected,
        external_approval_required=False,
        external_approval_self_proven=False,
    )


def author_runtime_observation_manifest(
    *,
    runtime_source_root: Path,
    runtime_role: str,
    entrypoint: str,
    output_path: Path,
) -> ManifestAuthoringResult:
    """Observe one complete runtime closure without self-promoting it to authority."""

    if runtime_role not in {ROLE_PYTHON_RUNTIME, ROLE_GIT_RUNTIME}:
        raise R002FDeploymentManifestAuthoringError("runtime role is invalid")
    if not isinstance(runtime_source_root, Path):
        raise TypeError("runtime_source_root must be pathlib.Path")
    if not isinstance(entrypoint, str) or not entrypoint:
        raise TypeError("entrypoint must be non-empty str")
    if not isinstance(output_path, Path):
        raise TypeError("output_path must be pathlib.Path")

    root = runtime_source_root.expanduser().absolute()
    manifest = build_sealed_runtime_manifest(
        root,
        runtime_role=runtime_role,
        entrypoint=entrypoint,
    )
    verify_sealed_runtime_tree(root, manifest)
    data = manifest.to_bytes()
    digest = _publish_manifest(
        output_path.expanduser().absolute(),
        data,
        max_bytes=MAX_RUNTIME_MANIFEST_BYTES,
        label=f"R002F {runtime_role} observation manifest",
    )
    return ManifestAuthoringResult(
        manifest_path=str(output_path.expanduser().absolute()),
        manifest_sha256=digest,
        manifest_role=runtime_role,
        reviewed_commit=None,
        external_approval_required=True,
        external_approval_self_proven=False,
    )


__all__ = [
    "ManifestAuthoringResult",
    "R002FDeploymentManifestAuthoringError",
    "author_reviewed_project_manifest",
    "author_runtime_observation_manifest",
]
