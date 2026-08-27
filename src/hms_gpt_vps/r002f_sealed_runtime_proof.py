from __future__ import annotations

from pathlib import Path
from typing import Callable

from .qualification_file_authority import path_chain_has_redirect
from .r002f_sealed_execution_acl import (
    build_exact_readonly_acl_powershell,
    validate_acl_evidence,
)
from .r002f_sealed_execution_manifest import (
    SealedExecutionTreeManifest,
    verify_sealed_execution_tree,
)
from .r002f_sealed_runtime_authority_support import (
    R002FSealedRuntimeAuthorityError,
)
from .r002f_sealed_runtime_host import run_system_powershell_json
from .r002f_sealed_runtime_manifest import (
    ROLE_GIT_RUNTIME,
    ROLE_PYTHON_RUNTIME,
    SealedRuntimeManifest,
    verify_sealed_runtime_tree,
)


def prove_acl(
    root: Path,
    *,
    expected_entry_count: int,
    system_directory: Path,
    powershell_runner: Callable[..., dict[str, object]] | None,
) -> None:
    script = build_exact_readonly_acl_powershell(root, reconcile=False)
    if powershell_runner is None:
        evidence = run_system_powershell_json(
            script,
            system_directory=system_directory,
            timeout_seconds=60,
        )
    else:
        evidence = powershell_runner(script, timeout_seconds=60)
    validate_acl_evidence(
        evidence,
        root=root,
        expected_entry_count=expected_entry_count,
        reconcile=False,
    )


def prove_project_tree(
    root: Path,
    data: bytes,
    *,
    reviewed_commit: str,
    system_directory: Path,
    powershell_runner: Callable[..., dict[str, object]] | None,
) -> SealedExecutionTreeManifest:
    manifest = SealedExecutionTreeManifest.from_bytes(data)
    if manifest.reviewed_commit != reviewed_commit:
        raise R002FSealedRuntimeAuthorityError(
            "sealed project reviewed commit differs from external authority"
        )
    count = manifest.file_count + manifest.directory_count
    prove_acl(
        root,
        expected_entry_count=count,
        system_directory=system_directory,
        powershell_runner=powershell_runner,
    )
    verify_sealed_execution_tree(root, manifest)
    prove_acl(
        root,
        expected_entry_count=count,
        system_directory=system_directory,
        powershell_runner=powershell_runner,
    )
    return manifest


def prove_runtime_tree(
    root: Path,
    data: bytes,
    *,
    runtime_role: str,
    system_directory: Path,
    powershell_runner: Callable[..., dict[str, object]] | None,
) -> tuple[SealedRuntimeManifest, Path]:
    manifest = SealedRuntimeManifest.from_bytes(data)
    if manifest.runtime_role != runtime_role:
        label = "Python" if runtime_role == ROLE_PYTHON_RUNTIME else "Git"
        raise R002FSealedRuntimeAuthorityError(
            f"runtime manifest is not {label} authority"
        )
    count = manifest.file_count + manifest.directory_count
    prove_acl(
        root,
        expected_entry_count=count,
        system_directory=system_directory,
        powershell_runner=powershell_runner,
    )
    verify_sealed_runtime_tree(root, manifest)
    prove_acl(
        root,
        expected_entry_count=count,
        system_directory=system_directory,
        powershell_runner=powershell_runner,
    )
    executable = (
        root / Path(manifest.entrypoint.replace("/", __import__("os").sep))
    ).absolute()
    if path_chain_has_redirect(executable) or not executable.is_file():
        raise R002FSealedRuntimeAuthorityError(
            f"sealed {runtime_role} executable is invalid"
        )
    return manifest, executable
