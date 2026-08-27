from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Callable, Mapping

from .agent_package import _validate_relative_package_path
from .external_mcp_command_flow_contract import canonical_git_sha1
from .r002f_reviewed_checkout_authority import require_reviewed_clean_checkout
from .r002f_reviewed_git_environment import checkout_validation_environment
from .r002f_reviewed_toolchain_authority import (
    canonical_sha256,
    pin_reviewed_git_executable,
)
from .r002f_sealed_execution_manifest import SealedExecutionTreeManifest

_ALLOWED_BLOB_MODES = frozenset({"100644", "100755"})
_MAX_TREE_FILES = 8192
_MAX_TREE_OUTPUT_BYTES = 64 * 1024 * 1024


class R002FReviewedGitTreeAuthorityError(RuntimeError):
    pass


def _parse_ls_tree_z(data: bytes) -> dict[str, str]:
    if not isinstance(data, bytes) or not data:
        raise R002FReviewedGitTreeAuthorityError(
            "reviewed Git tree output must be non-empty bytes"
        )
    if len(data) > _MAX_TREE_OUTPUT_BYTES:
        raise R002FReviewedGitTreeAuthorityError(
            "reviewed Git tree output exceeds safety bound"
        )
    if not data.endswith(b"\x00"):
        raise R002FReviewedGitTreeAuthorityError(
            "reviewed Git tree output is not NUL terminated"
        )

    entries = data[:-1].split(b"\x00")
    if not entries or len(entries) > _MAX_TREE_FILES:
        raise R002FReviewedGitTreeAuthorityError(
            "reviewed Git tree file count is outside bounds"
        )

    mapping: dict[str, str] = {}
    folded: set[str] = set()
    for entry in entries:
        try:
            header, raw_path = entry.split(b"\t", 1)
            mode_raw, type_raw, object_raw = header.split(b" ", 2)
            mode = mode_raw.decode("ascii")
            object_type = type_raw.decode("ascii")
            object_id = object_raw.decode("ascii")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise R002FReviewedGitTreeAuthorityError(
                "reviewed Git tree entry encoding/shape is invalid"
            ) from exc

        if mode not in _ALLOWED_BLOB_MODES or object_type != "blob":
            raise R002FReviewedGitTreeAuthorityError(
                "reviewed Git tree contains unsupported mode/object type"
            )
        canonical_git_sha1(object_id)
        try:
            normalized = _validate_relative_package_path(path)
        except ValueError as exc:
            raise R002FReviewedGitTreeAuthorityError(str(exc)) from exc
        if any(ord(char) < 32 for char in normalized):
            raise R002FReviewedGitTreeAuthorityError(
                "reviewed Git tree path contains control characters"
            )
        key = normalized.casefold()
        if key in folded:
            raise R002FReviewedGitTreeAuthorityError(
                "reviewed Git tree contains duplicate/case-colliding paths"
            )
        folded.add(key)
        mapping[normalized] = object_id
    return mapping


def _read_reviewed_git_tree(
    repo_root: Path,
    expected_commit: str,
    *,
    git_executable: Path,
    git_executable_sha256: str,
    environment: Mapping[str, str],
    command_runner: Callable[..., object],
) -> dict[str, str]:
    expected = canonical_git_sha1(expected_commit)
    git_sha = canonical_sha256(
        git_executable_sha256,
        "reviewed Git executable SHA-256",
    )
    safe_environment = checkout_validation_environment(environment)
    with pin_reviewed_git_executable(git_executable, git_sha) as pinned_git:
        pinned_git.assert_stable()
        completed = command_runner(
            [
                pinned_git.executable_path,
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-C",
                str(repo_root),
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                expected,
            ],
            cwd=str(repo_root),
            env=dict(safe_environment),
            check=False,
            capture_output=True,
            text=False,
            timeout=60.0,
        )
        pinned_git.assert_stable()

    returncode = getattr(completed, "returncode", None)
    stdout = getattr(completed, "stdout", None)
    if (
        not isinstance(returncode, int)
        or isinstance(returncode, bool)
        or returncode != 0
    ):
        raise R002FReviewedGitTreeAuthorityError(
            "reviewed Git tree authority command failed"
        )
    if not isinstance(stdout, bytes):
        raise R002FReviewedGitTreeAuthorityError(
            "reviewed Git tree authority stdout is invalid"
        )
    return _parse_ls_tree_z(stdout)


def verify_project_manifest_against_reviewed_git_tree(
    manifest: SealedExecutionTreeManifest,
    *,
    repo_root: Path,
    expected_commit: str,
    git_executable: Path,
    git_executable_sha256: str,
    environment: Mapping[str, str] | None = None,
    checkout_validator: Callable[..., None] = require_reviewed_clean_checkout,
    command_runner: Callable[..., object] = subprocess.run,
) -> None:
    """Re-bind a project manifest to the exact externally reviewed Git commit."""

    if not isinstance(manifest, SealedExecutionTreeManifest):
        raise TypeError("manifest must be SealedExecutionTreeManifest")
    manifest.validate()
    if not isinstance(repo_root, Path):
        raise TypeError("repo_root must be pathlib.Path")
    if not isinstance(git_executable, Path):
        raise TypeError("git_executable must be pathlib.Path")

    expected = canonical_git_sha1(expected_commit)
    if manifest.reviewed_commit != expected:
        raise R002FReviewedGitTreeAuthorityError(
            "project manifest reviewed_commit differs from reviewed Git authority"
        )
    git_sha = canonical_sha256(
        git_executable_sha256,
        "reviewed Git executable SHA-256",
    )
    source = os.environ if environment is None else environment
    safe_environment = checkout_validation_environment(source)
    root = repo_root.expanduser().absolute()
    git_path = git_executable.expanduser().absolute()

    checkout_validator(
        root,
        expected,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=safe_environment,
        command_runner=command_runner,
    )
    reviewed = _read_reviewed_git_tree(
        root,
        expected,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=safe_environment,
        command_runner=command_runner,
    )
    checkout_validator(
        root,
        expected,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=safe_environment,
        command_runner=command_runner,
    )

    manifest_mapping = {item.path: item.git_blob_sha1 for item in manifest.files}
    if manifest_mapping != reviewed:
        raise R002FReviewedGitTreeAuthorityError(
            "project manifest Git blob mapping differs from reviewed commit tree"
        )


__all__ = [
    "R002FReviewedGitTreeAuthorityError",
    "verify_project_manifest_against_reviewed_git_tree",
]
