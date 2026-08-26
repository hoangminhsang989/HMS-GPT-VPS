from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Callable, Mapping, Sequence

from .external_mcp_command_flow_contract import canonical_git_sha1
from .qualification_file_authority import path_chain_has_redirect, require_existing_directory
from .r002f_reviewed_git_environment import checkout_validation_environment

_GIT_SAFE_OVERRIDES = (
    ("core.fsmonitor", "false"),
    ("core.untrackedCache", "false"),
)


class R002FReviewedCheckoutAuthorityError(RuntimeError):
    pass


def _same_lexical_path(left: str | Path, right: str | Path) -> bool:
    return os.path.normcase(os.path.abspath(str(left))) == os.path.normcase(
        os.path.abspath(str(right))
    )


def _run_git_text(
    repo_root: Path,
    argv: Sequence[str],
    *,
    environment: Mapping[str, str],
    command_runner: Callable[..., object],
) -> str:
    command: list[str] = ["git"]
    for key, value in _GIT_SAFE_OVERRIDES:
        command.extend(["-c", f"{key}={value}"])
    command.extend(["-C", str(repo_root), *argv])
    completed = command_runner(
        command,
        cwd=str(repo_root),
        env=dict(environment),
        check=False,
        capture_output=True,
        text=True,
        timeout=60.0,
    )
    returncode = getattr(completed, "returncode", None)
    stdout = getattr(completed, "stdout", None)
    if not isinstance(returncode, int) or isinstance(returncode, bool) or returncode != 0:
        raise R002FReviewedCheckoutAuthorityError(
            "reviewed checkout Git authority command failed"
        )
    if not isinstance(stdout, str):
        raise R002FReviewedCheckoutAuthorityError(
            "reviewed checkout Git authority stdout is invalid"
        )
    return stdout


def require_reviewed_clean_checkout(
    repo_root: Path,
    expected_commit: str,
    *,
    environment: Mapping[str, str] | None = None,
    command_runner: Callable[..., object] = subprocess.run,
) -> None:
    """Bind a checkout to an externally supplied reviewed commit authority."""

    if not isinstance(repo_root, Path):
        raise TypeError("repo_root must be pathlib.Path")
    expected = canonical_git_sha1(expected_commit)
    root = require_existing_directory(repo_root, label="reviewed qualification repo root")
    if path_chain_has_redirect(root):
        raise R002FReviewedCheckoutAuthorityError(
            "reviewed qualification repo root traverses a link or reparse point"
        )
    source = os.environ if environment is None else environment
    safe_environment = checkout_validation_environment(source)

    top_level = _run_git_text(
        root,
        ["rev-parse", "--show-toplevel"],
        environment=safe_environment,
        command_runner=command_runner,
    ).strip()
    if not top_level or not _same_lexical_path(top_level, root):
        raise R002FReviewedCheckoutAuthorityError(
            "Git top-level differs from reviewed qualification repo authority"
        )

    actual = _run_git_text(
        root,
        ["rev-parse", "--verify", "HEAD"],
        environment=safe_environment,
        command_runner=command_runner,
    ).strip()
    if actual != expected:
        raise R002FReviewedCheckoutAuthorityError(
            "qualification checkout HEAD differs from reviewed runner commit"
        )

    status = _run_git_text(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"],
        environment=safe_environment,
        command_runner=command_runner,
    )
    if status:
        raise R002FReviewedCheckoutAuthorityError(
            "reviewed qualification checkout contains modified, untracked, or ignored content"
        )

    flags = _run_git_text(
        root,
        ["ls-files", "-v", "-z"],
        environment=safe_environment,
        command_runner=command_runner,
    )
    entries = [entry for entry in flags.split("\x00") if entry]
    if not entries or any(not entry.startswith("H ") for entry in entries):
        raise R002FReviewedCheckoutAuthorityError(
            "reviewed qualification checkout contains non-normal index authority flags"
        )
