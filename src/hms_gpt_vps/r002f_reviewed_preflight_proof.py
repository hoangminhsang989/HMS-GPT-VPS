from __future__ import annotations

import hashlib
from pathlib import Path

from .qualification_file_authority import (
    path_chain_has_redirect,
    read_file_pinned,
    require_existing_directory,
    write_json_create_only,
)
from .r002f_execution_preflight import render_powershell_command
from .r002f_reviewed_toolchain_authority import canonical_sha256

MAX_COMPONENT_PROOF_BYTES = 128 * 1024
MAX_FINAL_PROOF_BYTES = 192 * 1024


class R002FReviewedPreflightProofError(RuntimeError):
    pass


def validate_final_proof_path(path: Path, repo_root: Path) -> Path:
    authority = path.expanduser().absolute()
    if authority.exists() or authority.is_symlink():
        raise FileExistsError("reviewed preflight proof path must be new")
    parent = require_existing_directory(authority.parent, label="reviewed preflight proof parent")
    if path_chain_has_redirect(parent) or path_chain_has_redirect(authority):
        raise PermissionError("reviewed preflight proof authority is redirected")
    root = repo_root.expanduser().absolute()
    try:
        authority.relative_to(root)
    except ValueError:
        return authority
    raise ValueError("reviewed preflight proof must be outside the source checkout")


def component_path_for(final_proof_path: Path) -> Path:
    return final_proof_path.with_name(final_proof_path.name + ".component.json")


def component_digest(path: Path) -> str:
    data = read_file_pinned(
        path,
        max_bytes=MAX_COMPONENT_PROOF_BYTES,
        label="R002F component execution preflight proof",
        allow_empty=False,
    )
    return hashlib.sha256(data).hexdigest()


def _require_absolute_python_executable(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("python_executable must be pathlib.Path")
    authority = path.expanduser().absolute()
    if not authority.is_absolute() or path_chain_has_redirect(authority):
        raise R002FReviewedPreflightProofError(
            "reviewed Python executable authority is redirected or non-absolute"
        )
    if not authority.is_file():
        raise R002FReviewedPreflightProofError(
            "reviewed Python executable authority is not a regular file"
        )
    return authority


def reviewed_one_shot_argv(
    component_argv: object,
    *,
    expected_commit: str,
    repo_root: Path,
    python_executable: Path,
    git_executable: Path,
    git_executable_sha256: str,
) -> list[str]:
    if (
        not isinstance(component_argv, list)
        or len(component_argv) < 3
        or any(not isinstance(value, str) or not value for value in component_argv)
    ):
        raise R002FReviewedPreflightProofError("component one-shot argv is invalid")

    repo = repo_root.expanduser().absolute()
    expected_script = (
        repo / "scripts" / "run_r002f_one_shot_production_qualification.py"
    ).absolute()
    observed_script = Path(component_argv[1]).expanduser().absolute()
    if observed_script != expected_script:
        raise R002FReviewedPreflightProofError(
            "component one-shot script path differs from reviewed repo authority"
        )

    tail = list(component_argv[2:])
    indexes = [index for index, value in enumerate(tail) if value == "--runner-source-commit"]
    if len(indexes) != 1:
        raise R002FReviewedPreflightProofError(
            "component one-shot argv runner-source authority is ambiguous"
        )
    index = indexes[0]
    if index + 1 >= len(tail) or tail[index + 1] != expected_commit:
        raise R002FReviewedPreflightProofError(
            "component one-shot argv runner-source commit differs from reviewed authority"
        )
    forbidden = {
        "--reviewed-runner-source-commit",
        "--git-executable",
        "--git-executable-sha256",
    }
    if any(value in forbidden for value in tail):
        raise R002FReviewedPreflightProofError(
            "component one-shot argv unexpectedly contains reviewed toolchain authority"
        )

    python_path = _require_absolute_python_executable(python_executable)
    git_path = git_executable.expanduser().absolute()
    git_sha = canonical_sha256(
        git_executable_sha256,
        "reviewed Git executable SHA-256",
    )

    tail[index + 2:index + 2] = [
        "--reviewed-runner-source-commit",
        expected_commit,
        "--git-executable",
        str(git_path),
        "--git-executable-sha256",
        git_sha,
    ]
    return [
        str(python_path),
        "-I",
        "-X",
        "utf8",
        str(expected_script),
        *tail,
    ]


def publish_reviewed_preflight_proof(path: Path, proof: dict[str, object]) -> None:
    write_json_create_only(
        path,
        proof,
        max_bytes=MAX_FINAL_PROOF_BYTES,
        label="R002F reviewed execution preflight proof",
    )


def render_reviewed_command(argv: list[str]) -> str:
    return render_powershell_command(argv)
