from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True

_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def _path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = path.expanduser().absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            return True
        try:
            attributes = int(getattr(candidate.lstat(), "st_file_attributes", 0))
        except FileNotFoundError:
            continue
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    return False


def _bootstrap_reviewed_src(argv: list[str]) -> Path:
    if sys.flags.isolated != 1:
        raise SystemExit(
            "reviewed R002F one-shot runner must be launched with Python -I isolated mode"
        )
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repo-root", required=True, type=Path)
    args, _ = parser.parse_known_args(argv)
    repo = args.repo_root.expanduser().absolute()
    src = (repo / "src").absolute()
    scripts = (repo / "scripts").absolute()
    if (
        _path_chain_has_redirect(repo)
        or _path_chain_has_redirect(src)
        or _path_chain_has_redirect(scripts)
        or not repo.is_dir()
        or not src.is_dir()
        or not scripts.is_dir()
        or src.parent != repo
        or scripts.parent != repo
    ):
        raise SystemExit("reviewed R002F bootstrap repo/src/scripts authority is invalid")
    sys.path.insert(0, str(src))
    return repo


_BOOTSTRAP_REPO_ROOT = _bootstrap_reviewed_src(sys.argv[1:])

from hms_gpt_vps.external_mcp_command_flow_contract import canonical_git_sha1
from hms_gpt_vps.r002f_one_shot_production_qualification import (
    R002FOneShotProductionQualificationRequest,
    run_r002f_one_shot_production_qualification,
)
from hms_gpt_vps.r002f_reviewed_checkout_authority import (
    require_reviewed_clean_checkout,
)
from hms_gpt_vps.r002f_reviewed_git_environment import (
    sanitize_git_control_environment,
)
from hms_gpt_vps.r002f_reviewed_toolchain_authority import canonical_sha256


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the staged R002F Windows production qualification chain once using "
            "an externally reviewed commit and Git executable authority. This entrypoint "
            "requires Python -I before any project import."
        )
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--runner-source-commit", required=True)
    parser.add_argument("--reviewed-runner-source-commit", required=True)
    parser.add_argument("--git-executable", required=True, type=Path)
    parser.add_argument("--git-executable-sha256", required=True)
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
    repo_root = args.repo_root.expanduser().absolute()
    if repo_root != _BOOTSTRAP_REPO_ROOT:
        raise ValueError("repo_root changed after isolated bootstrap")

    runner_commit = canonical_git_sha1(args.runner_source_commit)
    reviewed_commit = canonical_git_sha1(args.reviewed_runner_source_commit)
    if runner_commit != reviewed_commit:
        raise ValueError(
            "runner_source_commit differs from reviewed_runner_source_commit authority"
        )
    git_sha = canonical_sha256(
        args.git_executable_sha256,
        "reviewed Git executable SHA-256",
    )
    git_path = args.git_executable.expanduser().absolute()

    sanitized_environment = sanitize_git_control_environment(os.environ)
    require_reviewed_clean_checkout(
        repo_root,
        reviewed_commit,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=sanitized_environment,
    )

    request = R002FOneShotProductionQualificationRequest(
        repo_root=repo_root,
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

    def reviewed_checkout_validator(
        checkout_repo_root: Path,
        expected_commit: str,
        *,
        environment,
    ) -> None:
        require_reviewed_clean_checkout(
            checkout_repo_root,
            expected_commit,
            git_executable=git_path,
            git_executable_sha256=git_sha,
            environment=environment,
        )

    result = run_r002f_one_shot_production_qualification(
        request,
        environment=sanitized_environment,
        python_executable=sys.executable,
        checkout_validator=reviewed_checkout_validator,
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
