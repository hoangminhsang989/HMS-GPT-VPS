from __future__ import annotations

import hashlib
from pathlib import Path

from .qualification_file_authority import read_file_pinned
from .r002f_sealed_runtime_authority_support import SealedTreeAuthority


def build_preflight_proof(
    *,
    ready: bool,
    component: dict[str, object],
    component_path: Path,
    reviewed_commit: str,
    repo_evidence: Path,
    authority: SealedTreeAuthority,
    sealed_argv: list[str] | None,
) -> dict[str, object]:
    component_bytes = read_file_pinned(
        component_path,
        max_bytes=128 * 1024,
        label="R002F sealed preflight component proof",
        allow_empty=False,
    )
    return {
        "schema_version": 1,
        "qualification": "R002F_SEALED_EXECUTION_PREFLIGHT",
        "status": (
            "READY_FOR_SEALED_ONE_SHOT_EXECUTION"
            if ready
            else str(component.get("status", "BLOCKED_COMPONENT_PREFLIGHT"))
        ),
        "ready": ready,
        "reviewed_runner_source_commit": reviewed_commit,
        "repo_evidence_root": str(repo_evidence),
        "execution_root": str(authority.execution_root),
        "execution_manifest_sha256": authority.execution_manifest_sha256,
        "python_runtime_root": str(authority.python_runtime_root),
        "python_runtime_manifest_sha256": (
            authority.python_runtime_manifest_sha256
        ),
        "git_runtime_root": str(authority.git_runtime_root),
        "git_runtime_manifest_sha256": authority.git_runtime_manifest_sha256,
        "system_directory": str(authority.system_directory),
        "component_preflight_sha256": hashlib.sha256(component_bytes).hexdigest(),
        "component_status": component.get("status"),
        "missing_authority": component.get("missing_authority", []),
        "host_blockers": component.get("host_blockers", []),
        "authority_blockers": component.get("authority_blockers", []),
        "sealed_execution_tree_proven": True,
        "python_runtime_closure_proven": True,
        "git_runtime_closure_proven": True,
        "execution_started": False,
        "hyperv_mutated": False,
        "bridge_started": False,
        "tunnel_started": False,
        "one_shot_argv": sealed_argv,
    }
