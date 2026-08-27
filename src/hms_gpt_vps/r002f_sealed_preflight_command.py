from __future__ import annotations

from pathlib import Path

from .r002f_sealed_runtime_authority_support import SealedTreeAuthority


def within(path: Path, root: Path) -> bool:
    try:
        path.expanduser().absolute().relative_to(root.expanduser().absolute())
        return True
    except ValueError:
        return False


def remove_pair(argv: list[str], flag: str) -> None:
    indexes = [i for i, item in enumerate(argv) if item == flag]
    if len(indexes) != 1 or indexes[0] + 1 >= len(argv):
        raise ValueError(f"component argv lacks exact {flag} authority")
    del argv[indexes[0] : indexes[0] + 2]


def build_sealed_argv(
    raw: object,
    *,
    authority: SealedTreeAuthority,
    reviewed_commit: str,
    execution_manifest: Path,
    python_runtime_manifest: Path,
) -> list[str]:
    if (
        not isinstance(raw, list)
        or len(raw) < 4
        or any(not isinstance(item, str) or not item for item in raw)
    ):
        raise ValueError("component one-shot argv is invalid")
    tail = list(raw[2:])
    remove_pair(tail, "--repo-root")
    forbidden = {
        "--execution-root",
        "--execution-manifest",
        "--execution-manifest-sha256",
        "--python-runtime-root",
        "--python-runtime-manifest",
        "--python-runtime-manifest-sha256",
    }
    if any(item in forbidden for item in tail):
        raise ValueError(
            "component argv unexpectedly contains sealed authority flags"
        )
    indexes = [
        index
        for index, item in enumerate(tail)
        if item == "--runner-source-commit"
    ]
    if (
        len(indexes) != 1
        or indexes[0] + 1 >= len(tail)
        or tail[indexes[0] + 1] != reviewed_commit
    ):
        raise ValueError(
            "component argv runner commit differs from sealed authority"
        )
    script = (
        authority.execution_root
        / "scripts"
        / "run_r002f_sealed_one_shot_production_qualification.py"
    )
    return [
        str(authority.python_executable),
        "-I",
        "-B",
        "-X",
        "utf8",
        str(script),
        "--execution-root",
        str(authority.execution_root),
        "--execution-manifest",
        str(execution_manifest.expanduser().absolute()),
        "--execution-manifest-sha256",
        authority.execution_manifest_sha256,
        "--python-runtime-root",
        str(authority.python_runtime_root),
        "--python-runtime-manifest",
        str(python_runtime_manifest.expanduser().absolute()),
        "--python-runtime-manifest-sha256",
        authority.python_runtime_manifest_sha256,
        *tail,
    ]
