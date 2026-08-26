from __future__ import annotations

import argparse
import json
from pathlib import Path

from hms_gpt_vps.r002f_one_shot_production_qualification import (
    R002FOneShotProductionQualificationRequest,
    run_r002f_one_shot_production_qualification,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the staged R002F Windows production qualification chain once: "
            "managed Hyper-V Agent -> HMSBridge composite activation -> authenticated "
            "Agent transport -> OpenAI control-plane MCP read -> cross-proof binding. "
            "The run directory must be new and outside the source checkout."
        )
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--runner-source-commit", required=True)
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
    request = R002FOneShotProductionQualificationRequest(
        repo_root=args.repo_root,
        run_dir=args.run_dir,
        runner_source_commit=args.runner_source_commit,
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
    result = run_r002f_one_shot_production_qualification(request)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
