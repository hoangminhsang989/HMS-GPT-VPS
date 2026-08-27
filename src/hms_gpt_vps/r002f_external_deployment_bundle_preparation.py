from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PureWindowsPath

from .bridge_composite_activation_runner import (
    BOOTSTRAP_PASSWORD_ENV,
    BOOTSTRAP_USERNAME_ENV,
)
from .qualification_file_authority import (
    read_file_pinned,
    write_bytes_create_only,
)
from .r002f_external_deployment_bundle import (
    MAX_BUNDLE_BYTES,
    R002FExternalDeploymentAuthorityBundle,
)
from .r002f_external_deployment_bundle_types import (
    LAUNCHER_FILENAME,
    REVIEWED_LAUNCHER_SHA256,
    REVIEWED_STAGE0_SHA256,
    STAGE0_FILENAME,
    PinnedArtifact,
    PreflightAuthority,
    SealedTreeAuthority,
    direct_child,
    same,
    windows_absolute,
)
from .r002f_sealed_execution_manifest import (
    MAX_MANIFEST_BYTES as MAX_PROJECT_MANIFEST_BYTES,
    SealedExecutionTreeManifest,
    verify_sealed_execution_tree,
)
from .r002f_sealed_runtime_manifest import (
    MAX_MANIFEST_BYTES as MAX_RUNTIME_MANIFEST_BYTES,
    ROLE_GIT_RUNTIME,
    ROLE_PYTHON_RUNTIME,
    SealedRuntimeManifest,
    verify_sealed_runtime_tree,
)

MAX_LAUNCHER_BYTES = 64 * 1024
MAX_STAGE0_BYTES = 128 * 1024


class R002FExternalDeploymentPreparationError(RuntimeError):
    pass


@dataclass(frozen=True)
class R002FExternalDeploymentPreparationRequest:
    reviewed_commit: str
    authority_parent: Path
    launcher_path: Path
    stage0_path: Path
    project_source_root: Path
    project_manifest_path: Path
    project_destination_root: Path
    python_source_root: Path
    python_manifest_path: Path
    python_destination_root: Path
    git_source_root: Path
    git_manifest_path: Path
    git_destination_root: Path
    repo_evidence_root: Path
    preflight_proof_path: Path
    stage0_proof_path: Path
    launcher_proof_path: Path
    bundle_path: Path
    preflight: PreflightAuthority


@dataclass(frozen=True)
class R002FExternalDeploymentPreparationResult:
    bundle_path: str
    bundle_sha256: str
    reviewed_commit: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "qualification": "R002F_EXTERNAL_DEPLOYMENT_BUNDLE_PREPARATION",
            "status": "BUNDLE_CREATE_ONLY_PUBLISHED",
            "bundle_path": self.bundle_path,
            "bundle_sha256": self.bundle_sha256,
            "reviewed_commit": self.reviewed_commit,
            "execution_started": False,
            "hyperv_mutated": False,
            "bridge_started": False,
            "tunnel_started": False,
        }



def _require_windows_host() -> None:
    if os.name != "nt":
        raise R002FExternalDeploymentPreparationError(
            "R002F deployment bundle preparation is Windows-only"
        )

def _absolute(path: Path, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} must be pathlib.Path")
    value = str(path)
    windows_absolute(value, label)
    return Path(value)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_canonical_project_manifest(path: Path) -> tuple[SealedExecutionTreeManifest, bytes]:
    data = read_file_pinned(
        path,
        max_bytes=MAX_PROJECT_MANIFEST_BYTES,
        label="R002F reviewed project manifest",
    )
    manifest = SealedExecutionTreeManifest.from_bytes(data)
    if manifest.to_bytes() != data:
        raise R002FExternalDeploymentPreparationError(
            "reviewed project manifest is not in canonical byte form"
        )
    return manifest, data


def _read_canonical_runtime_manifest(
    path: Path,
    *,
    expected_role: str,
    label: str,
) -> tuple[SealedRuntimeManifest, bytes]:
    data = read_file_pinned(
        path,
        max_bytes=MAX_RUNTIME_MANIFEST_BYTES,
        label=label,
    )
    manifest = SealedRuntimeManifest.from_bytes(data)
    if manifest.to_bytes() != data:
        raise R002FExternalDeploymentPreparationError(
            f"{label} is not in canonical byte form"
        )
    if manifest.runtime_role != expected_role:
        raise R002FExternalDeploymentPreparationError(
            f"{label} runtime role differs"
        )
    return manifest, data


def _require_reviewed_artifact(
    path: Path,
    *,
    filename: str,
    expected_sha256: str,
    max_bytes: int,
    label: str,
) -> bytes:
    if PureWindowsPath(str(path)).name != filename:
        raise R002FExternalDeploymentPreparationError(f"{label} filename differs")
    data = read_file_pinned(path, max_bytes=max_bytes, label=label)
    if _sha256_bytes(data) != expected_sha256:
        raise R002FExternalDeploymentPreparationError(
            f"{label} SHA-256 differs from reviewed authority"
        )
    return data


def _validate_bundle_output_path(
    request: R002FExternalDeploymentPreparationRequest,
    *,
    authority_parent: Path,
) -> Path:
    output = _absolute(request.bundle_path, "bundle_path")
    if not direct_child(str(output), str(authority_parent)):
        raise R002FExternalDeploymentPreparationError(
            "bundle_path must be a direct child of authority_parent"
        )
    reserved = (
        request.launcher_path,
        request.stage0_path,
        request.project_manifest_path,
        request.python_manifest_path,
        request.git_manifest_path,
        request.project_destination_root,
        request.python_destination_root,
        request.git_destination_root,
        request.preflight_proof_path,
        request.stage0_proof_path,
        request.launcher_proof_path,
    )
    if any(same(str(output), str(_absolute(path, "reserved authority path"))) for path in reserved):
        raise R002FExternalDeploymentPreparationError(
            "bundle_path must be distinct from deployment authority paths"
        )
    return output


def prepare_r002f_external_deployment_bundle(
    request: R002FExternalDeploymentPreparationRequest,
) -> R002FExternalDeploymentPreparationResult:
    """Verify exact source/manifests and publish one canonical bundle create-only.

    This is a preparation operation only. It does not render or execute the
    launcher, start services, mutate Hyper-V, retire bootstrap credentials, or
    promote any production proof boolean.
    """

    if not isinstance(request, R002FExternalDeploymentPreparationRequest):
        raise TypeError("request must be R002FExternalDeploymentPreparationRequest")
    _require_windows_host()
    if any(
        isinstance(os.environ.get(name), str) and bool(os.environ.get(name))
        for name in (BOOTSTRAP_USERNAME_ENV, BOOTSTRAP_PASSWORD_ENV)
    ):
        raise R002FExternalDeploymentPreparationError(
            "bootstrap secret environment must be absent during bundle preparation"
        )

    authority = _absolute(request.authority_parent, "authority_parent")
    if same(str(PureWindowsPath(str(authority)).parent), str(authority)):
        raise R002FExternalDeploymentPreparationError(
            "authority_parent must not be a filesystem root"
        )

    launcher = _absolute(request.launcher_path, "launcher_path")
    stage0 = _absolute(request.stage0_path, "stage0_path")
    if not direct_child(str(launcher), str(authority)):
        raise R002FExternalDeploymentPreparationError(
            "launcher_path must be a direct child of authority_parent"
        )
    if not direct_child(str(stage0), str(authority)):
        raise R002FExternalDeploymentPreparationError(
            "stage0_path must be a direct child of authority_parent"
        )
    _require_reviewed_artifact(
        launcher,
        filename=LAUNCHER_FILENAME,
        expected_sha256=REVIEWED_LAUNCHER_SHA256,
        max_bytes=MAX_LAUNCHER_BYTES,
        label="reviewed launcher",
    )
    _require_reviewed_artifact(
        stage0,
        filename=STAGE0_FILENAME,
        expected_sha256=REVIEWED_STAGE0_SHA256,
        max_bytes=MAX_STAGE0_BYTES,
        label="reviewed stage0",
    )
    output = _validate_bundle_output_path(request, authority_parent=authority)

    project_source = _absolute(request.project_source_root, "project_source_root")
    project_manifest_path = _absolute(
        request.project_manifest_path, "project_manifest_path"
    )
    project_manifest, project_bytes = _read_canonical_project_manifest(
        project_manifest_path
    )
    if project_manifest.reviewed_commit != request.reviewed_commit:
        raise R002FExternalDeploymentPreparationError(
            "project manifest reviewed_commit differs from requested authority"
        )
    verify_sealed_execution_tree(project_source, project_manifest)

    python_source = _absolute(request.python_source_root, "python_source_root")
    python_manifest_path = _absolute(
        request.python_manifest_path, "python_manifest_path"
    )
    python_manifest, python_bytes = _read_canonical_runtime_manifest(
        python_manifest_path,
        expected_role=ROLE_PYTHON_RUNTIME,
        label="R002F Python runtime manifest",
    )
    verify_sealed_runtime_tree(python_source, python_manifest)

    git_source = _absolute(request.git_source_root, "git_source_root")
    git_manifest_path = _absolute(request.git_manifest_path, "git_manifest_path")
    git_manifest, git_bytes = _read_canonical_runtime_manifest(
        git_manifest_path,
        expected_role=ROLE_GIT_RUNTIME,
        label="R002F Git runtime manifest",
    )
    verify_sealed_runtime_tree(git_source, git_manifest)

    project_destination = _absolute(
        request.project_destination_root, "project_destination_root"
    )
    python_destination = _absolute(
        request.python_destination_root, "python_destination_root"
    )
    git_destination = _absolute(
        request.git_destination_root, "git_destination_root"
    )
    repo_evidence = _absolute(request.repo_evidence_root, "repo_evidence_root")
    preflight_proof = _absolute(
        request.preflight_proof_path, "preflight_proof_path"
    )
    stage0_proof = _absolute(request.stage0_proof_path, "stage0_proof_path")
    launcher_proof = _absolute(
        request.launcher_proof_path, "launcher_proof_path"
    )

    bundle = R002FExternalDeploymentAuthorityBundle(
        reviewed_commit=request.reviewed_commit,
        authority_parent=str(authority),
        launcher=PinnedArtifact(
            path=str(launcher), sha256=REVIEWED_LAUNCHER_SHA256
        ),
        stage0=PinnedArtifact(path=str(stage0), sha256=REVIEWED_STAGE0_SHA256),
        project=SealedTreeAuthority(
            source_root=str(project_source),
            manifest_path=str(project_manifest_path),
            manifest_sha256=_sha256_bytes(project_bytes),
            destination_root=str(project_destination),
        ),
        python_runtime=SealedTreeAuthority(
            source_root=str(python_source),
            manifest_path=str(python_manifest_path),
            manifest_sha256=_sha256_bytes(python_bytes),
            destination_root=str(python_destination),
        ),
        git_runtime=SealedTreeAuthority(
            source_root=str(git_source),
            manifest_path=str(git_manifest_path),
            manifest_sha256=_sha256_bytes(git_bytes),
            destination_root=str(git_destination),
        ),
        repo_evidence_root=str(repo_evidence),
        preflight_proof_path=str(preflight_proof),
        stage0_proof_path=str(stage0_proof),
        launcher_proof_path=str(launcher_proof),
        preflight=request.preflight,
    )
    data = bundle.to_bytes()
    write_bytes_create_only(
        output,
        data,
        max_bytes=MAX_BUNDLE_BYTES,
        label="R002F external deployment authority bundle",
    )
    readback = read_file_pinned(
        output,
        max_bytes=MAX_BUNDLE_BYTES,
        label="R002F external deployment authority bundle",
    )
    if readback != data:
        raise R002FExternalDeploymentPreparationError(
            "deployment bundle readback differs from canonical bytes"
        )
    observed = _sha256_bytes(readback)
    if observed != bundle.sha256:
        raise R002FExternalDeploymentPreparationError(
            "deployment bundle readback SHA-256 differs"
        )
    return R002FExternalDeploymentPreparationResult(
        bundle_path=str(output),
        bundle_sha256=observed,
        reviewed_commit=request.reviewed_commit,
    )


__all__ = [
    "R002FExternalDeploymentPreparationError",
    "R002FExternalDeploymentPreparationRequest",
    "R002FExternalDeploymentPreparationResult",
    "prepare_r002f_external_deployment_bundle",
]
