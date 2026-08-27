from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from .qualification_file_authority import path_chain_has_redirect, read_file_pinned

MAX_AUTHORITY_MANIFEST_BYTES = 4 * 1024 * 1024


class R002FSealedRuntimeAuthorityError(RuntimeError):
    pass


def canonical_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise R002FSealedRuntimeAuthorityError(
            f"{label} must be canonical lowercase SHA-256"
        )
    return value


def within(path: Path, root: Path) -> bool:
    try:
        path.expanduser().absolute().relative_to(root.expanduser().absolute())
        return True
    except ValueError:
        return False


def roots_overlap(left: Path, right: Path) -> bool:
    return within(left, right) or within(right, left)


def require_manifest_outside_roots(
    path: Path,
    roots: tuple[Path, ...],
    label: str,
) -> None:
    authority = path.expanduser().absolute()
    if any(within(authority, root) for root in roots):
        raise R002FSealedRuntimeAuthorityError(
            f"{label} must be outside all sealed roots"
        )


def read_manifest(
    path: Path,
    *,
    expected_sha256: str,
    label: str,
    root: Path,
) -> bytes:
    authority = path.expanduser().absolute()
    sealed_root = root.expanduser().absolute()
    if path_chain_has_redirect(authority):
        raise R002FSealedRuntimeAuthorityError(f"{label} path is redirected")
    try:
        authority.relative_to(sealed_root)
    except ValueError:
        pass
    else:
        raise R002FSealedRuntimeAuthorityError(
            f"{label} must be outside its sealed root"
        )
    data = read_file_pinned(
        authority,
        max_bytes=MAX_AUTHORITY_MANIFEST_BYTES,
        label=label,
        allow_empty=False,
    )
    if hashlib.sha256(data).hexdigest() != canonical_sha256(
        expected_sha256, f"{label} SHA-256"
    ):
        raise R002FSealedRuntimeAuthorityError(f"{label} SHA-256 differs")
    return data


@dataclass(frozen=True)
class SealedTreeAuthority:
    execution_root: Path
    reviewed_commit: str
    execution_manifest_sha256: str
    python_runtime_root: Path
    python_runtime_manifest_sha256: str
    python_executable: Path
    git_runtime_root: Path | None
    git_runtime_manifest_sha256: str | None
    git_executable: Path | None
    system_directory: Path
