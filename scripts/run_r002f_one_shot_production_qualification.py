from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from hms_gpt_vps.external_mcp_command_flow_contract import canonical_git_sha1
from hms_gpt_vps.r002f_one_shot_production_qualification import (
    R002FOneShotProductionQualificationRequest,
    run_r002f_one_shot_production_qualification,
)
from hms_gpt_vps.r002f_reviewed_execution_preflight import (
    require_reviewed_clean_checkout,
    sanitize_git_control_environment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the staged R002F Windows production qualification chain once: "
            "managed Hyper-V Agent -> HMSBridge composite activation -> authenticated "
            "Agent transport -> OpenAI control-plane MCP read -> cross-proof binding. "
            "The run directory must be new and outside the source checkout, and the "
            "runner checkout must match an externally reviewed commit authority."
        )
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--runner-source-commit", required=True)
    parser.add_argument("--reviewed-runner-source-commit", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--package-root", required=True, type=Path)
    parser.add_argument("--package-manifest", required=True, type=Path)
    parser.add_argument("--runtime-config", required=True, type=Path)
    parser.add_argument("--instance-registry", required=True, type=Path)
    parser.add_argument("--provision-state", required=True, type=Path)
    parser.add_argument("--instance-runtime-dir", required=True, type=Path)
    parser.add_argument("--bridge-device-credential", required=True, type=Path)
    parser.add_argument("--trust-root-certificate", required=True, type=Path)
    parser.add_argument("--challenge-source-commit", required=True)
    parser.add_argument("--challenge-workspace-path", required=True)
    parser.add_argument("--challenge-expected-sha256", required=True)
    parser.add_argument("--max-reconcile-steps", type=int, default=8)
    parser.add_argument("--external-timeout", type=float, default=300.0)
    parser.add_argument("--step-timeout", type=float, default=900.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner_commit = canonical_git_sha1(args.runner_source_commit)
    reviewed_commit = canonical_git_sha1(args.reviewed_runner_source_commit)
    if runner_commit != reviewed_commit:
        raise ValueError(
            "runner_source_commit differs from reviewed_runner_source_commit authority"
        )

    sanitized_environment = sanitize_git_control_environment(os.environ)
    require_reviewed_clean_checkout(
        args.repo_root,
        reviewed_commit,
        environment=sanitized_environment,
    )

    request = R002FOneShotProductionQualificationRequest(
        repo_root=args.repo_root,
        run_dir=args.run_dir,
        runner_source_commit=runner_commit,
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
    result = run_r002f_one_shot_production_qualification(
        request,
        environment=sanitized_environment,
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
