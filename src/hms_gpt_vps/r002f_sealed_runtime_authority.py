from __future__ import annotations

from pathlib import Path
from typing import Callable

from .qualification_file_authority import path_chain_has_redirect
from .r002f_sealed_runtime_authority_support import (
    R002FSealedRuntimeAuthorityError,
    SealedTreeAuthority,
    canonical_sha256,
    read_manifest,
    require_manifest_outside_roots,
    roots_overlap,
)
from .r002f_sealed_runtime_host import (
    sealed_child_environment,
    system_directory as resolve_system_directory,
)
from .r002f_sealed_runtime_manifest import ROLE_GIT_RUNTIME, ROLE_PYTHON_RUNTIME
from .r002f_sealed_runtime_proof import prove_project_tree, prove_runtime_tree


def prove_sealed_tree_authority(
    *,
    execution_root: Path,
    execution_manifest_path: Path,
    execution_manifest_sha256: str,
    reviewed_commit: str,
    python_runtime_root: Path,
    python_runtime_manifest_path: Path,
    python_runtime_manifest_sha256: str,
    git_runtime_root: Path | None = None,
    git_runtime_manifest_path: Path | None = None,
    git_runtime_manifest_sha256: str | None = None,
    powershell_runner: Callable[..., dict[str, object]] | None = None,
    system_directory: Path | None = None,
) -> SealedTreeAuthority:
    execution_root = execution_root.expanduser().absolute()
    python_runtime_root = python_runtime_root.expanduser().absolute()
    git_candidate = (
        git_runtime_root.expanduser().absolute()
        if git_runtime_root is not None
        else None
    )
    roots = (
        (execution_root, python_runtime_root)
        if git_candidate is None
        else (execution_root, python_runtime_root, git_candidate)
    )
    for index, left in enumerate(roots):
        for right in roots[index + 1 :]:
            if roots_overlap(left, right):
                raise R002FSealedRuntimeAuthorityError(
                    "sealed roots must be separate and non-nested"
                )

    require_manifest_outside_roots(
        execution_manifest_path, roots, "sealed project execution manifest"
    )
    require_manifest_outside_roots(
        python_runtime_manifest_path, roots, "sealed Python runtime manifest"
    )
    if git_runtime_manifest_path is not None:
        require_manifest_outside_roots(
            git_runtime_manifest_path, roots, "sealed Git runtime manifest"
        )

    system = (
        resolve_system_directory()
        if system_directory is None
        else system_directory.expanduser().absolute()
    )
    if path_chain_has_redirect(system) or not system.is_dir():
        raise R002FSealedRuntimeAuthorityError(
            "Windows System32 authority is invalid"
        )

    execution_data = read_manifest(
        execution_manifest_path,
        expected_sha256=execution_manifest_sha256,
        label="sealed project execution manifest",
        root=execution_root,
    )
    prove_project_tree(
        execution_root,
        execution_data,
        reviewed_commit=reviewed_commit,
        system_directory=system,
        powershell_runner=powershell_runner,
    )

    python_data = read_manifest(
        python_runtime_manifest_path,
        expected_sha256=python_runtime_manifest_sha256,
        label="sealed Python runtime manifest",
        root=python_runtime_root,
    )
    _, python_executable = prove_runtime_tree(
        python_runtime_root,
        python_data,
        runtime_role=ROLE_PYTHON_RUNTIME,
        system_directory=system,
        powershell_runner=powershell_runner,
    )

    git_root = None
    git_executable = None
    git_manifest_sha = None
    supplied = (
        git_runtime_root is not None
        or git_runtime_manifest_path is not None
        or git_runtime_manifest_sha256 is not None
    )
    if supplied:
        if (
            git_runtime_root is None
            or git_runtime_manifest_path is None
            or git_runtime_manifest_sha256 is None
        ):
            raise R002FSealedRuntimeAuthorityError(
                "Git runtime authority must be supplied as a complete triple"
            )
        assert git_candidate is not None
        git_root = git_candidate
        git_data = read_manifest(
            git_runtime_manifest_path,
            expected_sha256=git_runtime_manifest_sha256,
            label="sealed Git runtime manifest",
            root=git_root,
        )
        _, git_executable = prove_runtime_tree(
            git_root,
            git_data,
            runtime_role=ROLE_GIT_RUNTIME,
            system_directory=system,
            powershell_runner=powershell_runner,
        )
        git_manifest_sha = canonical_sha256(
            git_runtime_manifest_sha256,
            "sealed Git runtime manifest SHA-256",
        )

    return SealedTreeAuthority(
        execution_root=execution_root,
        reviewed_commit=reviewed_commit,
        execution_manifest_sha256=canonical_sha256(
            execution_manifest_sha256,
            "sealed project execution manifest SHA-256",
        ),
        python_runtime_root=python_runtime_root,
        python_runtime_manifest_sha256=canonical_sha256(
            python_runtime_manifest_sha256,
            "sealed Python runtime manifest SHA-256",
        ),
        python_executable=python_executable,
        git_runtime_root=git_root,
        git_runtime_manifest_sha256=git_manifest_sha,
        git_executable=git_executable,
        system_directory=system,
    )
