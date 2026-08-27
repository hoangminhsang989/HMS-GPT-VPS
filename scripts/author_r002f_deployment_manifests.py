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

from hms_gpt_vps.r002f_deployment_manifest_authoring import (
    author_reviewed_project_manifest,
    author_runtime_observation_manifest,
)
from hms_gpt_vps.r002f_sealed_runtime_manifest import (
    ROLE_GIT_RUNTIME,
    ROLE_PYTHON_RUNTIME,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Author R002F project/runtime manifests without self-promoting "
            "runtime observations into external authority."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    project = sub.add_parser("project")
    project.add_argument("--project-source-root", required=True, type=Path)
    project.add_argument("--repo-evidence-root", required=True, type=Path)
    project.add_argument("--reviewed-commit", required=True)
    project.add_argument("--git-executable", required=True, type=Path)
    project.add_argument("--git-executable-sha256", required=True)
    project.add_argument("--output", required=True, type=Path)

    for name, role in (
        ("python-runtime", ROLE_PYTHON_RUNTIME),
        ("git-runtime", ROLE_GIT_RUNTIME),
    ):
        runtime = sub.add_parser(name)
        runtime.set_defaults(runtime_role=role)
        runtime.add_argument("--runtime-source-root", required=True, type=Path)
        runtime.add_argument("--entrypoint", required=True)
        runtime.add_argument("--output", required=True, type=Path)

    args = parser.parse_args(argv)
    if args.command == "project":
        result = author_reviewed_project_manifest(
            project_source_root=args.project_source_root,
            repo_evidence_root=args.repo_evidence_root,
            reviewed_commit=args.reviewed_commit,
            git_executable=args.git_executable,
            git_executable_sha256=args.git_executable_sha256,
            output_path=args.output,
        )
    else:
        result = author_runtime_observation_manifest(
            runtime_source_root=args.runtime_source_root,
            runtime_role=args.runtime_role,
            entrypoint=args.entrypoint,
            output_path=args.output,
        )
    print(json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
