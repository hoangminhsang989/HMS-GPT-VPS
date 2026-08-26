from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from hms_gpt_vps.r002f_execution_preflight import R002FExecutionPreflightRequest
from hms_gpt_vps.r002f_reviewed_execution_preflight import (
    run_r002f_reviewed_execution_preflight,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Bind the R002F read-only production preflight to an externally reviewed "
            "runner commit, sanitize Git checkout authority, and publish the only "
            "one-shot command authorized for live execution."
        )
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--expected-runner-source-commit", required=True)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--package-manifest", type=Path)
    parser.add_argument("--runtime-config", type=Path)
    parser.add_argument("--instance-registry", type=Path)
    parser.add_argument("--instance-runtime-dir", type=Path)
    parser.add_argument("--bridge-device-credential", type=Path)
    parser.add_argument("--trust-root-certificate", type=Path)
    parser.add_argument("--challenge-source-commit")
    parser.add_argument("--challenge-workspace-path")
    parser.add_argument("--challenge-expected-sha256")
    parser.add_argument("--max-reconcile-steps", type=int, default=8)
    parser.add_argument("--external-timeout", type=float, default=300.0)
    parser.add_argument("--step-timeout", type=float, default=900.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    component_request = R002FExecutionPreflightRequest(
        repo_root=args.repo_root,
        proof_path=args.proof,
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
    result = run_r002f_reviewed_execution_preflight(
        component_request,
        expected_runner_source_commit=args.expected_runner_source_commit,
        final_proof_path=args.proof,
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result.get("ready") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
