from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def _bootstrap() -> None:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))


_bootstrap()

from hms_gpt_vps.r002f_external_deployment_bundle_preparation import (
    R002FExternalDeploymentPreparationRequest,
    prepare_r002f_external_deployment_bundle,
)
from hms_gpt_vps.r002f_external_deployment_bundle_types import PreflightAuthority


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify reviewed R002F project/Python/Git authorities, require "
            "externally-approved runtime manifest digests, re-bind the project "
            "manifest to the exact reviewed Git tree, and publish one canonical "
            "external deployment bundle create-only."
        )
    )
    add = parser.add_argument
    add("--reviewed-commit", required=True)
    add("--authority-parent", required=True, type=Path)
    add("--launcher", required=True, type=Path)
    add("--stage0", required=True, type=Path)
    add("--project-source-root", required=True, type=Path)
    add("--project-manifest", required=True, type=Path)
    add("--execution-root", required=True, type=Path)
    add("--python-source-root", required=True, type=Path)
    add("--python-manifest", required=True, type=Path)
    add("--python-manifest-sha256", required=True)
    add("--python-runtime-root", required=True, type=Path)
    add("--git-source-root", required=True, type=Path)
    add("--git-manifest", required=True, type=Path)
    add("--git-manifest-sha256", required=True)
    add("--git-runtime-root", required=True, type=Path)
    add("--repo-evidence-root", required=True, type=Path)
    add("--reviewed-git-executable", required=True, type=Path)
    add("--reviewed-git-executable-sha256", required=True)
    add("--preflight-proof", required=True, type=Path)
    add("--stage0-proof", required=True, type=Path)
    add("--launcher-proof", required=True, type=Path)
    add("--bundle", required=True, type=Path)
    add("--run-dir", required=True)
    add("--package-root", required=True)
    add("--package-manifest", required=True)
    add("--runtime-config", required=True)
    add("--instance-registry", required=True)
    add("--instance-runtime-dir", required=True)
    add("--bridge-device-credential", required=True)
    add("--trust-root-certificate", required=True)
    add("--challenge-source-commit", required=True)
    add("--challenge-workspace-path", required=True)
    add("--challenge-expected-sha256", required=True)
    add("--max-reconcile-steps", required=True, type=int)
    add("--external-timeout", required=True, type=float)
    add("--step-timeout", required=True, type=float)
    args = parser.parse_args(argv)

    preflight = PreflightAuthority(
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
    request = R002FExternalDeploymentPreparationRequest(
        reviewed_commit=args.reviewed_commit,
        authority_parent=args.authority_parent,
        launcher_path=args.launcher,
        stage0_path=args.stage0,
        project_source_root=args.project_source_root,
        project_manifest_path=args.project_manifest,
        project_destination_root=args.execution_root,
        python_source_root=args.python_source_root,
        python_manifest_path=args.python_manifest,
        python_manifest_sha256=args.python_manifest_sha256,
        python_destination_root=args.python_runtime_root,
        git_source_root=args.git_source_root,
        git_manifest_path=args.git_manifest,
        git_manifest_sha256=args.git_manifest_sha256,
        git_destination_root=args.git_runtime_root,
        repo_evidence_root=args.repo_evidence_root,
        reviewed_git_executable=args.reviewed_git_executable,
        reviewed_git_executable_sha256=args.reviewed_git_executable_sha256,
        preflight_proof_path=args.preflight_proof,
        stage0_proof_path=args.stage0_proof,
        launcher_proof_path=args.launcher_proof,
        bundle_path=args.bundle,
        preflight=preflight,
    )
    result = prepare_r002f_external_deployment_bundle(request)
    print(json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
