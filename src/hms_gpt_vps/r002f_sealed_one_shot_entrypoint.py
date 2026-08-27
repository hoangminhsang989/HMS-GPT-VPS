from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

from .external_mcp_command_flow_contract import canonical_git_sha1
from .r002f_sealed_one_shot_args import build_parser
from .qualification_file_authority import (
    read_file_pinned,
    write_json_create_only,
)
from .r002f_one_shot_production_qualification import (
    FINAL_MANIFEST_NAME,
    R002FOneShotProductionQualificationRequest,
    run_r002f_one_shot_production_qualification,
)
from .r002f_sealed_runtime_authority import (
    prove_sealed_tree_authority,
    sealed_child_environment,
)

_BINDING_NAME = "07-sealed-execution-binding.json"


def _request(args, authority, reviewed_commit: str):
    return R002FOneShotProductionQualificationRequest(
        repo_root=authority.execution_root,
        run_dir=args.run_dir,
        runner_source_commit=reviewed_commit,
        instance_id=args.instance_id,
        vm_name=args.vm_name,
        package_root=args.package_root,
        package_manifest=args.package_manifest,
        runtime_config=args.runtime_config,
        instance_registry=args.instance_registry,
        provision_state=args.provision_state,
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
    reviewed_commit = canonical_git_sha1(args.runner_source_commit)
    authority = prove_sealed_tree_authority(
        execution_root=execution_root,
        execution_manifest_path=args.execution_manifest,
        execution_manifest_sha256=args.execution_manifest_sha256,
        reviewed_commit=reviewed_commit,
        python_runtime_root=args.python_runtime_root,
        python_runtime_manifest_path=args.python_runtime_manifest,
        python_runtime_manifest_sha256=args.python_runtime_manifest_sha256,
    )
    if Path(sys.executable).expanduser().absolute() != authority.python_executable:
        raise ValueError(
            "sealed entrypoint is not running under approved Python runtime"
        )
    safe_environment = sealed_child_environment(
        os.environ,
        system_directory=authority.system_directory,
    )

    def sealed_validator(
        repo_root: Path,
        expected_commit: str,
        *,
        environment,
    ) -> None:
        if repo_root.expanduser().absolute() != authority.execution_root:
            raise ValueError("coordinator escaped sealed execution root")
        if canonical_git_sha1(expected_commit) != authority.reviewed_commit:
            raise ValueError("coordinator reviewed commit drifted")
        prove_sealed_tree_authority(
            execution_root=authority.execution_root,
            execution_manifest_path=args.execution_manifest,
            execution_manifest_sha256=authority.execution_manifest_sha256,
            reviewed_commit=authority.reviewed_commit,
            python_runtime_root=authority.python_runtime_root,
            python_runtime_manifest_path=args.python_runtime_manifest,
            python_runtime_manifest_sha256=authority.python_runtime_manifest_sha256,
            system_directory=authority.system_directory,
        )

    result = run_r002f_one_shot_production_qualification(
        _request(args, authority, reviewed_commit),
        environment=safe_environment,
        python_executable=str(authority.python_executable),
        checkout_validator=sealed_validator,
    )
    final_path = args.run_dir.expanduser().absolute() / FINAL_MANIFEST_NAME
    final_bytes = read_file_pinned(
        final_path,
        max_bytes=64 * 1024,
        label="R002F one-shot final manifest",
        allow_empty=False,
    )
    binding = {
        "schema_version": 1,
        "qualification": "R002F_SEALED_ONE_SHOT_EXECUTION_BINDING",
        "status": "ONE_SHOT_BOUND_TO_SEALED_RUNTIME_AUTHORITY",
        "reviewed_commit": authority.reviewed_commit,
        "execution_root": str(authority.execution_root),
        "execution_manifest_sha256": authority.execution_manifest_sha256,
        "python_runtime_root": str(authority.python_runtime_root),
        "python_runtime_manifest_sha256": authority.python_runtime_manifest_sha256,
        "python_executable": str(authority.python_executable),
        "system_directory": str(authority.system_directory),
        "one_shot_manifest_sha256": hashlib.sha256(final_bytes).hexdigest(),
        "sealed_execution_tree_proven": True,
        "python_runtime_closure_proven": True,
        "git_runtime_required_for_live_execution": False,
        "chatgpt_ui_origin_proven": False,
        "chatgpt_app_oauth_client_proven": False,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
    }
    write_json_create_only(
        args.run_dir.expanduser().absolute() / _BINDING_NAME,
        binding,
        max_bytes=64 * 1024,
        label="R002F sealed one-shot execution binding",
    )
    print(
        json.dumps(
            {"component": result, "sealed_binding": binding},
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0
