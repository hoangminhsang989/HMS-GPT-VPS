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


def reviewed_one_shot_argv(component_argv: object, *, expected_commit: str) -> list[str]:
    if (
        not isinstance(component_argv, list)
        or not component_argv
        or any(not isinstance(value, str) or not value for value in component_argv)
    ):
        raise R002FReviewedPreflightProofError("component one-shot argv is invalid")
    argv = list(component_argv)
    indexes = [index for index, value in enumerate(argv) if value == "--runner-source-commit"]
    if len(indexes) != 1:
        raise R002FReviewedPreflightProofError(
            "component one-shot argv runner-source authority is ambiguous"
        )
    index = indexes[0]
    if index + 1 >= len(argv) or argv[index + 1] != expected_commit:
        raise R002FReviewedPreflightProofError(
            "component one-shot argv runner-source commit differs from reviewed authority"
        )
    if "--reviewed-runner-source-commit" in argv:
        raise R002FReviewedPreflightProofError(
            "component one-shot argv unexpectedly contains reviewed authority"
        )
    argv[index + 2:index + 2] = ["--reviewed-runner-source-commit", expected_commit]
    return argv


def publish_reviewed_preflight_proof(path: Path, proof: dict[str, object]) -> None:
    write_json_create_only(
        path,
        proof,
        max_bytes=MAX_FINAL_PROOF_BYTES,
        label="R002F reviewed execution preflight proof",
    )


def render_reviewed_command(argv: list[str]) -> str:
    return render_powershell_command(argv)
