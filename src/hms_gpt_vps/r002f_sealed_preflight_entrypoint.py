from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from .external_mcp_command_flow_contract import canonical_git_sha1
from .qualification_file_authority import path_chain_has_redirect, write_json_create_only
from .r002f_execution_preflight import (
    R002FExecutionPreflightRequest,
    run_r002f_execution_preflight,
)
from .r002f_sealed_preflight_args import build_parser
from .r002f_sealed_preflight_command import build_sealed_argv, within
from .r002f_sealed_preflight_result import build_preflight_proof
from .r002f_sealed_runtime_authority import (
    prove_sealed_tree_authority,
    sealed_child_environment,
)

_MAX_PROOF_BYTES = 192 * 1024
_SECRETS = (
    "HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME",
    "HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD",
)


def _component_request(args, repo_evidence: Path, component_path: Path):
    return R002FExecutionPreflightRequest(
        repo_root=repo_evidence,
        proof_path=component_path,
        run_dir=args.run_dir,
        package_root=args.package_root,
        package_manifest=args.package_manifest,
        runtime_config=args.runtime_config,
        instance_registry=args.instance_registry,
        instance_runtime_dir=args.instance_runtime_dir,
        bridge_device_credential=args.bridge_device_credential,
        trust_root_certificate=args.trust_root_certificate,
        challenge_source_commit=args.challenge_source_commit,
        challenge_workspace_path=args.challenge_workspace_path,
        challenge_expected_sha256=args.challenge_expected_sha256,
        max_reconcile_steps=args.max_reconcile_steps,
        external_timeout_seconds=args.external_timeout,
        step_timeout_seconds=args.step_timeout,
    )


def main(argv: list[str], *, bootstrap_root: Path) -> int:
    args = build_parser().parse_args(argv)
    execution_root = args.execution_root.expanduser().absolute()
    if execution_root != bootstrap_root:
        raise ValueError("execution_root changed after isolated bootstrap")
    reviewed_commit = canonical_git_sha1(args.reviewed_runner_source_commit)
    authority = prove_sealed_tree_authority(
        execution_root=execution_root,
        execution_manifest_path=args.execution_manifest,
        execution_manifest_sha256=args.execution_manifest_sha256,
        reviewed_commit=reviewed_commit,
        python_runtime_root=args.python_runtime_root,
        python_runtime_manifest_path=args.python_runtime_manifest,
        python_runtime_manifest_sha256=args.python_runtime_manifest_sha256,
        git_runtime_root=args.git_runtime_root,
        git_runtime_manifest_path=args.git_runtime_manifest,
        git_runtime_manifest_sha256=args.git_runtime_manifest_sha256,
    )
    if Path(sys.executable).expanduser().absolute() != authority.python_executable:
        raise ValueError(
            "sealed preflight is not running under approved Python runtime"
        )
    if authority.git_executable is None or authority.git_runtime_root is None:
        raise ValueError("sealed Git runtime authority is required for preflight")

    repo_evidence = args.repo_evidence_root.expanduser().absolute()
    if path_chain_has_redirect(repo_evidence) or not repo_evidence.is_dir():
        raise ValueError("repo_evidence_root authority is invalid")
    roots = (
        authority.execution_root,
        authority.python_runtime_root,
        authority.git_runtime_root,
    )
    if any(
        within(repo_evidence, root) or within(root, repo_evidence)
        for root in roots
    ):
        raise ValueError("repo evidence root must be separate from sealed roots")
    proof_path = args.proof.expanduser().absolute()
    if any(within(proof_path, root) for root in roots):
        raise ValueError("sealed preflight proof must be outside sealed roots")
    if args.run_dir is not None:
        run_dir = args.run_dir.expanduser().absolute()
        if any(within(run_dir, root) for root in roots):
            raise ValueError("sealed one-shot run_dir must be outside sealed roots")

    safe_environment = sealed_child_environment(
        os.environ,
        system_directory=authority.system_directory,
        git_executable=authority.git_executable,
    )
    if any(name in safe_environment for name in _SECRETS):
        raise ValueError("sealed preflight must run before bootstrap secrets are set")

    old_environment = dict(os.environ)
    component_path = proof_path.with_name(proof_path.name + ".component.json")
    try:
        os.environ.clear()
        os.environ.update(safe_environment)
        component = run_r002f_execution_preflight(
            _component_request(args, repo_evidence, component_path),
            environment=safe_environment,
        )
    finally:
        os.environ.clear()
        os.environ.update(old_environment)

    runner = component.get("runner_source_commit")
    if runner is not None and runner != reviewed_commit:
        raise ValueError("repo evidence HEAD differs from sealed reviewed commit")
    ready = component.get("ready") is True
    if ready and runner != reviewed_commit:
        raise ValueError("ready component lacks exact reviewed checkout authority")
    sealed_argv = (
        build_sealed_argv(
            component.get("one_shot_argv"),
            authority=authority,
            reviewed_commit=reviewed_commit,
            execution_manifest=args.execution_manifest,
            python_runtime_manifest=args.python_runtime_manifest,
        )
        if ready
        else None
    )
    proof = build_preflight_proof(
        ready=ready,
        component=component,
        component_path=component_path,
        reviewed_commit=reviewed_commit,
        repo_evidence=repo_evidence,
        authority=authority,
        sealed_argv=sealed_argv,
    )
    write_json_create_only(
        proof_path,
        proof,
        max_bytes=_MAX_PROOF_BYTES,
        label="R002F sealed execution preflight proof",
    )
    print(json.dumps(proof, ensure_ascii=True, sort_keys=True))
    return 0 if ready else 2
