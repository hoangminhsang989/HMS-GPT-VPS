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
            "reviewed R002F preflight must be launched with Python -I isolated mode"
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

from hms_gpt_vps.r002f_execution_preflight import R002FExecutionPreflightRequest
from hms_gpt_vps.r002f_reviewed_execution_preflight import (
    run_r002f_reviewed_execution_preflight,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Bind the R002F read-only production preflight to externally reviewed "
            "runner + Git executable authority and publish only an isolated one-shot "
            "command. This script itself requires Python -I."
        )
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--expected-runner-source-commit", required=True)
    parser.add_argument("--git-executable", required=True, type=Path)
    parser.add_argument("--git-executable-sha256", required=True)
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
    repo_root = args.repo_root.expanduser().absolute()
    if repo_root != _BOOTSTRAP_REPO_ROOT:
        raise ValueError("repo_root changed after isolated bootstrap")
    component_request = R002FExecutionPreflightRequest(
        repo_root=repo_root,
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
        git_executable=args.git_executable,
        git_executable_sha256=args.git_executable_sha256,
        python_executable=Path(sys.executable),
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result.get("ready") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
