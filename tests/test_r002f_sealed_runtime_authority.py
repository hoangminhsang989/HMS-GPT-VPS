from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hms_gpt_vps.r002f_sealed_execution_manifest import (
    build_reviewed_project_manifest,
)
from hms_gpt_vps.r002f_sealed_runtime_authority import (
    prove_sealed_tree_authority,
    sealed_child_environment,
)
from hms_gpt_vps.r002f_sealed_runtime_manifest import (
    ROLE_GIT_RUNTIME,
    ROLE_PYTHON_RUNTIME,
    R002FSealedRuntimeError,
    build_sealed_runtime_manifest,
    verify_sealed_runtime_tree,
)


def _git_blob(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _write_manifest(path: Path, manifest) -> str:
    data = manifest.to_bytes()
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def test_runtime_manifest_closes_directory_namespace(tmp_path: Path) -> None:
    runtime = tmp_path / "python-runtime"
    runtime.mkdir()
    (runtime / "python.exe").write_bytes(b"python")
    (runtime / "DLLs").mkdir()
    (runtime / "DLLs" / "python311.dll").write_bytes(b"dll")
    manifest = build_sealed_runtime_manifest(
        runtime,
        runtime_role=ROLE_PYTHON_RUNTIME,
        entrypoint="python.exe",
    )
    verify_sealed_runtime_tree(runtime, manifest)
    (runtime / "extra").mkdir()
    with pytest.raises(R002FSealedRuntimeError):
        verify_sealed_runtime_tree(runtime, manifest)


def test_git_runtime_cannot_shadow_host_executables(tmp_path: Path) -> None:
    runtime = tmp_path / "git-runtime"
    runtime.mkdir()
    (runtime / "git.exe").write_bytes(b"git")
    (runtime / "powershell.exe").write_bytes(b"shadow")
    with pytest.raises(R002FSealedRuntimeError):
        build_sealed_runtime_manifest(
            runtime,
            runtime_role=ROLE_GIT_RUNTIME,
            entrypoint="git.exe",
        )


def test_authority_brackets_tree_hash_with_acl_proofs(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "scripts").mkdir()
    expected = {}
    for relative, data in {
        "src/a.py": b"a=1\n",
        "scripts/run.py": b"print('x')\n",
    }.items():
        path = project / relative
        path.write_bytes(data)
        expected[relative] = _git_blob(data)
    reviewed = "a" * 40
    project_manifest = build_reviewed_project_manifest(
        project,
        reviewed_commit=reviewed,
        expected_git_blobs=expected,
    )
    project_manifest_path = tmp_path / "project.json"
    project_sha = _write_manifest(project_manifest_path, project_manifest)

    python_root = tmp_path / "python"
    python_root.mkdir()
    (python_root / "python.exe").write_bytes(b"python")
    python_manifest = build_sealed_runtime_manifest(
        python_root,
        runtime_role=ROLE_PYTHON_RUNTIME,
        entrypoint="python.exe",
    )
    python_manifest_path = tmp_path / "python.json"
    python_sha = _write_manifest(python_manifest_path, python_manifest)
    system = tmp_path / "System32"
    system.mkdir()

    roots = [project, project, python_root, python_root]
    counts = [
        project_manifest.file_count + project_manifest.directory_count,
        project_manifest.file_count + project_manifest.directory_count,
        python_manifest.file_count + python_manifest.directory_count,
        python_manifest.file_count + python_manifest.directory_count,
    ]
    calls = []

    def runner(script: str, *, timeout_seconds: int):
        index = len(calls)
        calls.append(roots[index])
        return {
            "ready": True,
            "changed": False,
            "root": str(roots[index].absolute()),
            "entry_count": counts[index],
            "directory_acls_exact": True,
            "file_acls_exact": True,
            "reparse_point_found": False,
        }

    authority = prove_sealed_tree_authority(
        execution_root=project,
        execution_manifest_path=project_manifest_path,
        execution_manifest_sha256=project_sha,
        reviewed_commit=reviewed,
        python_runtime_root=python_root,
        python_runtime_manifest_path=python_manifest_path,
        python_runtime_manifest_sha256=python_sha,
        powershell_runner=runner,
        system_directory=system,
    )
    assert authority.python_executable == (python_root / "python.exe").absolute()
    assert calls == roots
