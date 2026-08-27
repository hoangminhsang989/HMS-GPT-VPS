from __future__ import annotations

from pathlib import Path

import pytest

import hms_gpt_vps.r002f_external_deployment_bundle_preparation as prep
from hms_gpt_vps.r002f_external_deployment_bundle_preparation import (
    R002FExternalDeploymentPreparationError,
    R002FExternalDeploymentPreparationRequest,
    prepare_r002f_external_deployment_bundle,
)
from hms_gpt_vps.r002f_external_deployment_bundle_types import PreflightAuthority
from hms_gpt_vps.r002f_sealed_execution_manifest import (
    SealedExecutionFile,
    SealedExecutionTreeManifest,
    TREE_ROLE_REVIEWED_PROJECT,
)
from hms_gpt_vps.r002f_sealed_runtime_manifest import (
    ROLE_GIT_RUNTIME,
    ROLE_PYTHON_RUNTIME,
    SealedRuntimeFile,
    SealedRuntimeManifest,
)


COMMIT = "a" * 40
SHA = "b" * 64


def _preflight() -> PreflightAuthority:
    return PreflightAuthority(
        run_dir=r"C:\inputs\run",
        package_root=r"C:\inputs\package",
        package_manifest=r"C:\inputs\agent-package.json",
        runtime_config=r"C:\inputs\agent-runtime.json",
        instance_registry=r"C:\inputs\instances.json",
        instance_runtime_dir=r"C:\inputs\instance-runtime",
        bridge_device_credential=r"C:\inputs\bridge-device.dpapi",
        trust_root_certificate=r"C:\inputs\trust-root.pem",
        challenge_source_commit="c" * 40,
        challenge_workspace_path=r"C:\inputs\challenge.txt",
        challenge_expected_sha256="d" * 64,
        max_reconcile_steps=8,
        external_timeout_seconds=300.0,
        step_timeout_seconds=900.0,
    )


def _request() -> R002FExternalDeploymentPreparationRequest:
    a = Path(r"C:\authority")
    return R002FExternalDeploymentPreparationRequest(
        reviewed_commit=COMMIT,
        authority_parent=a,
        launcher_path=Path(
            r"C:\authority\run_r002f_external_sealed_preparation_launcher.ps1"
        ),
        stage0_path=Path(
            r"C:\authority\run_r002f_external_sealed_preparation_stage0.ps1"
        ),
        project_source_root=Path(r"C:\source\project"),
        project_manifest_path=Path(r"C:\authority\project.manifest.json"),
        project_destination_root=Path(r"C:\authority\execution"),
        python_source_root=Path(r"C:\source\python"),
        python_manifest_path=Path(r"C:\authority\python.manifest.json"),
        python_destination_root=Path(r"C:\authority\python-runtime"),
        git_source_root=Path(r"C:\source\git"),
        git_manifest_path=Path(r"C:\authority\git.manifest.json"),
        git_destination_root=Path(r"C:\authority\git-runtime"),
        repo_evidence_root=Path(r"C:\source\repo-evidence"),
        reviewed_git_executable=Path(r"C:\toolchain\git.exe"),
        reviewed_git_executable_sha256=SHA,
        preflight_proof_path=Path(r"C:\authority\preflight.proof.json"),
        stage0_proof_path=Path(r"C:\authority\stage0.proof.json"),
        launcher_proof_path=Path(r"C:\authority\launcher.proof.json"),
        bundle_path=Path(r"C:\authority\deployment.bundle.json"),
        preflight=_preflight(),
    )


def _project_manifest(commit: str = COMMIT) -> SealedExecutionTreeManifest:
    return SealedExecutionTreeManifest(
        reviewed_commit=commit,
        tree_role=TREE_ROLE_REVIEWED_PROJECT,
        file_count=1,
        directory_count=0,
        total_size=1,
        files=(
            SealedExecutionFile(
                path="x.txt",
                size=1,
                sha256="1" * 64,
                git_blob_sha1="2" * 40,
            ),
        ),
    )


def _runtime_manifest(role: str) -> SealedRuntimeManifest:
    name = "python.exe" if role == ROLE_PYTHON_RUNTIME else "git.exe"
    return SealedRuntimeManifest(
        runtime_role=role,
        entrypoint=name,
        file_count=1,
        directory_count=0,
        total_size=1,
        files=(SealedRuntimeFile(path=name, size=1, sha256="3" * 64),),
    )


def _install_success_stubs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(prep, "_require_windows_host", lambda: None)
    monkeypatch.setattr(prep, "_require_reviewed_artifact", lambda *a, **k: b"x")
    monkeypatch.setattr(
        prep, "verify_project_manifest_against_reviewed_git_tree", lambda *a, **k: None
    )
    project = _project_manifest()
    python = _runtime_manifest(ROLE_PYTHON_RUNTIME)
    git = _runtime_manifest(ROLE_GIT_RUNTIME)
    payloads = {
        r"C:\authority\project.manifest.json": project.to_bytes(),
        r"C:\authority\python.manifest.json": python.to_bytes(),
        r"C:\authority\git.manifest.json": git.to_bytes(),
    }
    published: dict[str, bytes] = {}

    def read(path, **kwargs):
        key = str(path)
        if key == r"C:\authority\deployment.bundle.json":
            return published[key]
        return payloads[key]

    def write(path, data, **kwargs):
        key = str(path)
        if key in published:
            raise FileExistsError(key)
        published[key] = data
        return path

    monkeypatch.setattr(prep, "read_file_pinned", read)
    monkeypatch.setattr(prep, "write_bytes_create_only", write)
    monkeypatch.setattr(prep, "verify_sealed_execution_tree", lambda *a: None)
    monkeypatch.setattr(prep, "verify_sealed_runtime_tree", lambda *a: None)
    return payloads, published


def test_preparation_publishes_canonical_bundle_and_keeps_execution_false(monkeypatch):
    _, published = _install_success_stubs(monkeypatch)
    result = prepare_r002f_external_deployment_bundle(_request())
    raw = published[r"C:\authority\deployment.bundle.json"]
    bundle = prep.R002FExternalDeploymentAuthorityBundle.from_bytes(raw)

    assert result.bundle_sha256 == bundle.sha256
    assert bundle.reviewed_commit == COMMIT
    assert bundle.project.manifest_sha256 == prep._sha256_bytes(
        _project_manifest().to_bytes()
    )
    assert result.to_dict()["execution_started"] is False
    assert result.to_dict()["hyperv_mutated"] is False


def test_project_manifest_git_rebind_precedes_source_verification(monkeypatch):
    _install_success_stubs(monkeypatch)
    calls = []

    def rebind(manifest, **kwargs):
        calls.append(
            (
                "git-tree",
                manifest.reviewed_commit,
                str(kwargs["repo_root"]),
                str(kwargs["git_executable"]),
                kwargs["git_executable_sha256"],
            )
        )

    monkeypatch.setattr(prep, "verify_project_manifest_against_reviewed_git_tree", rebind)
    monkeypatch.setattr(
        prep,
        "verify_sealed_execution_tree",
        lambda root, manifest: calls.append(("project-source", str(root))),
    )
    prepare_r002f_external_deployment_bundle(_request())
    assert calls == [
        (
            "git-tree",
            COMMIT,
            r"C:\source\repo-evidence",
            r"C:\toolchain\git.exe",
            SHA,
        ),
        ("project-source", r"C:\source\project"),
    ]


def test_preparation_verifies_all_three_source_trees_before_publication(monkeypatch):
    _install_success_stubs(monkeypatch)
    calls = []
    monkeypatch.setattr(
        prep, "verify_sealed_execution_tree", lambda root, manifest: calls.append(("p", str(root)))
    )
    monkeypatch.setattr(
        prep, "verify_sealed_runtime_tree", lambda root, manifest: calls.append((manifest.runtime_role, str(root)))
    )
    prepare_r002f_external_deployment_bundle(_request())
    assert calls == [
        ("p", r"C:\source\project"),
        (ROLE_PYTHON_RUNTIME, r"C:\source\python"),
        (ROLE_GIT_RUNTIME, r"C:\source\git"),
    ]


def test_project_manifest_git_tree_mismatch_is_rejected_before_source_or_write(monkeypatch):
    _, published = _install_success_stubs(monkeypatch)
    source_calls = []

    def fail(*args, **kwargs):
        raise RuntimeError("Git blob mapping differs")

    monkeypatch.setattr(prep, "verify_project_manifest_against_reviewed_git_tree", fail)
    monkeypatch.setattr(
        prep,
        "verify_sealed_execution_tree",
        lambda *args: source_calls.append(True),
    )
    with pytest.raises(RuntimeError, match="Git blob mapping differs"):
        prepare_r002f_external_deployment_bundle(_request())
    assert source_calls == []
    assert published == {}


def test_project_manifest_commit_mismatch_is_rejected_before_write(monkeypatch):
    payloads, published = _install_success_stubs(monkeypatch)
    payloads[r"C:\authority\project.manifest.json"] = _project_manifest("e" * 40).to_bytes()
    with pytest.raises(R002FExternalDeploymentPreparationError, match="reviewed_commit"):
        prepare_r002f_external_deployment_bundle(_request())
    assert published == {}


def test_swapped_runtime_role_is_rejected(monkeypatch):
    payloads, published = _install_success_stubs(monkeypatch)
    payloads[r"C:\authority\python.manifest.json"] = _runtime_manifest(
        ROLE_GIT_RUNTIME
    ).to_bytes()
    with pytest.raises(R002FExternalDeploymentPreparationError, match="runtime role differs"):
        prepare_r002f_external_deployment_bundle(_request())
    assert published == {}


def test_noncanonical_manifest_bytes_are_rejected(monkeypatch):
    payloads, published = _install_success_stubs(monkeypatch)
    canonical = _project_manifest().to_bytes()
    payloads[r"C:\authority\project.manifest.json"] = canonical[:-1] + b" \n"
    with pytest.raises(R002FExternalDeploymentPreparationError, match="canonical"):
        prepare_r002f_external_deployment_bundle(_request())
    assert published == {}


def test_bundle_output_must_be_direct_child_and_distinct(monkeypatch):
    _, published = _install_success_stubs(monkeypatch)
    bad = _request()
    nested = R002FExternalDeploymentPreparationRequest(
        **{**bad.__dict__, "bundle_path": Path(r"C:\authority\nested\bundle.json")}
    )
    with pytest.raises(R002FExternalDeploymentPreparationError, match="direct child"):
        prepare_r002f_external_deployment_bundle(nested)
    assert published == {}

    alias = R002FExternalDeploymentPreparationRequest(
        **{**bad.__dict__, "bundle_path": bad.project_manifest_path}
    )
    with pytest.raises(R002FExternalDeploymentPreparationError, match="distinct"):
        prepare_r002f_external_deployment_bundle(alias)
    assert published == {}


def test_bootstrap_secret_environment_blocks_preparation(monkeypatch):
    _install_success_stubs(monkeypatch)
    monkeypatch.setenv(prep.BOOTSTRAP_PASSWORD_ENV, "secret")
    with pytest.raises(R002FExternalDeploymentPreparationError, match="secret environment"):
        prepare_r002f_external_deployment_bundle(_request())


def test_create_only_failure_is_not_reinterpreted(monkeypatch):
    _install_success_stubs(monkeypatch)

    def existing(*args, **kwargs):
        raise FileExistsError("already exists")

    monkeypatch.setattr(prep, "write_bytes_create_only", existing)
    with pytest.raises(FileExistsError):
        prepare_r002f_external_deployment_bundle(_request())


def test_source_verification_failure_prevents_bundle_write(monkeypatch):
    _, published = _install_success_stubs(monkeypatch)

    def fail(*args, **kwargs):
        raise RuntimeError("source drift")

    monkeypatch.setattr(prep, "verify_sealed_execution_tree", fail)
    with pytest.raises(RuntimeError, match="source drift"):
        prepare_r002f_external_deployment_bundle(_request())
    assert published == {}


def test_result_contains_no_secret_values(monkeypatch):
    _install_success_stubs(monkeypatch)
    result = prepare_r002f_external_deployment_bundle(_request())
    text = str(result.to_dict()).lower()
    assert "password" not in text
    assert "username" not in text


def test_reviewed_artifact_hash_mismatch_is_rejected(monkeypatch):
    monkeypatch.setattr(prep, "read_file_pinned", lambda *a, **k: b"wrong")
    with pytest.raises(R002FExternalDeploymentPreparationError, match="SHA-256"):
        prep._require_reviewed_artifact(
            Path(
                r"C:\authority\run_r002f_external_sealed_preparation_launcher.ps1"
            ),
            filename=prep.LAUNCHER_FILENAME,
            expected_sha256=prep.REVIEWED_LAUNCHER_SHA256,
            max_bytes=prep.MAX_LAUNCHER_BYTES,
            label="reviewed launcher",
        )


def test_non_windows_host_is_rejected_before_input_reads(monkeypatch):
    called = []
    monkeypatch.setattr(
        prep,
        "_require_windows_host",
        lambda: (_ for _ in ()).throw(
            R002FExternalDeploymentPreparationError("Windows-only")
        ),
    )
    monkeypatch.setattr(
        prep, "read_file_pinned", lambda *a, **k: called.append(True)
    )
    with pytest.raises(R002FExternalDeploymentPreparationError, match="Windows-only"):
        prepare_r002f_external_deployment_bundle(_request())
    assert called == []
