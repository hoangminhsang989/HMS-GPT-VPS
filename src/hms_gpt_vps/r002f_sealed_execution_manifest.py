from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Mapping

from .agent_package import (
    _iter_package_files,
    _resolve_package_root,
    _validate_relative_package_path,
)
from .qualification_file_authority import path_chain_has_redirect, read_file_pinned

SCHEMA_VERSION = 1
TREE_ROLE_REVIEWED_PROJECT = "reviewed-project"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TREE_FILES = 8192
MAX_TREE_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024


class R002FSealedExecutionTreeError(RuntimeError):
    pass


def _sha1(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise R002FSealedExecutionTreeError(
            f"{label} must be canonical lowercase SHA-1"
        )
    return value


def _sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise R002FSealedExecutionTreeError(
            f"{label} must be canonical lowercase SHA-256"
        )
    return value


def _relative(value: object) -> str:
    if not isinstance(value, str):
        raise R002FSealedExecutionTreeError("sealed execution path must be text")
    try:
        return _validate_relative_package_path(value)
    except ValueError as exc:
        raise R002FSealedExecutionTreeError(str(exc)) from exc


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def _implied_directories(paths: set[str] | tuple[str, ...]) -> set[str]:
    result: set[str] = set()
    for relative in paths:
        parts = PurePosixPath(relative).parts[:-1]
        for index in range(1, len(parts) + 1):
            result.add("/".join(parts[:index]))
    return result


def _actual_directories(root: Path) -> set[str]:
    authority = _resolve_package_root(root)
    result: set[str] = set()
    for current_text, dirnames, _ in os.walk(
        authority, topdown=True, followlinks=False
    ):
        current = Path(current_text)
        for dirname in dirnames:
            directory = current / dirname
            if path_chain_has_redirect(directory):
                raise R002FSealedExecutionTreeError(
                    "sealed execution tree contains redirected directory"
                )
            relative = directory.relative_to(authority).as_posix()
            _relative(relative)
            result.add(relative)
    return result


def _read(path: Path) -> bytes:
    return read_file_pinned(
        path,
        max_bytes=MAX_FILE_BYTES,
        label="R002F sealed execution file",
        allow_empty=True,
    )


@dataclass(frozen=True)
class SealedExecutionFile:
    path: str
    size: int
    sha256: str
    git_blob_sha1: str

    def validate(self) -> None:
        _relative(self.path)
        if (
            not isinstance(self.size, int)
            or isinstance(self.size, bool)
            or self.size < 0
            or self.size > MAX_FILE_BYTES
        ):
            raise R002FSealedExecutionTreeError(
                "sealed execution file size is invalid"
            )
        _sha256(self.sha256, "sealed execution file SHA-256")
        _sha1(self.git_blob_sha1, "sealed execution Git blob SHA-1")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "git_blob_sha1": self.git_blob_sha1,
        }

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> "SealedExecutionFile":
        if frozenset(raw) != frozenset(
            {"path", "size", "sha256", "git_blob_sha1"}
        ):
            raise R002FSealedExecutionTreeError(
                "sealed execution file fields are invalid"
            )
        path = raw.get("path")
        size = raw.get("size")
        sha256 = raw.get("sha256")
        blob = raw.get("git_blob_sha1")
        if (
            not isinstance(path, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not isinstance(sha256, str)
            or not isinstance(blob, str)
        ):
            raise R002FSealedExecutionTreeError(
                "sealed execution file field types are invalid"
            )
        item = cls(path=path, size=size, sha256=sha256, git_blob_sha1=blob)
        item.validate()
        return item


@dataclass(frozen=True)
class SealedExecutionTreeManifest:
    reviewed_commit: str
    tree_role: str
    file_count: int
    directory_count: int
    total_size: int
    files: tuple[SealedExecutionFile, ...]

    def validate(self) -> None:
        _sha1(self.reviewed_commit, "reviewed commit")
        if self.tree_role != TREE_ROLE_REVIEWED_PROJECT:
            raise R002FSealedExecutionTreeError(
                "sealed execution tree role must be reviewed-project"
            )
        if (
            not isinstance(self.file_count, int)
            or isinstance(self.file_count, bool)
            or not 1 <= self.file_count <= MAX_TREE_FILES
        ):
            raise R002FSealedExecutionTreeError(
                "sealed execution file_count is invalid"
            )
        if (
            not isinstance(self.directory_count, int)
            or isinstance(self.directory_count, bool)
            or not 0 <= self.directory_count <= MAX_TREE_FILES
        ):
            raise R002FSealedExecutionTreeError(
                "sealed execution directory_count is invalid"
            )
        if (
            not isinstance(self.total_size, int)
            or isinstance(self.total_size, bool)
            or not 0 <= self.total_size <= MAX_TREE_BYTES
        ):
            raise R002FSealedExecutionTreeError(
                "sealed execution total_size is invalid"
            )
        if len(self.files) != self.file_count:
            raise R002FSealedExecutionTreeError(
                "sealed execution file_count does not match files"
            )

        seen: set[str] = set()
        paths: list[str] = []
        total = 0
        for item in self.files:
            item.validate()
            folded = item.path.casefold()
            if folded in seen:
                raise R002FSealedExecutionTreeError(
                    "sealed execution tree contains duplicate/case-colliding paths"
                )
            seen.add(folded)
            paths.append(item.path)
            total += item.size
        if paths != sorted(paths, key=lambda value: (value.casefold(), value)):
            raise R002FSealedExecutionTreeError(
                "sealed execution files must be deterministically sorted"
            )
        if len(_implied_directories(tuple(paths))) != self.directory_count:
            raise R002FSealedExecutionTreeError(
                "sealed execution directory_count does not match file paths"
            )
        if total != self.total_size:
            raise R002FSealedExecutionTreeError(
                "sealed execution total_size does not match files"
            )

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": SCHEMA_VERSION,
            "reviewed_commit": self.reviewed_commit,
            "tree_role": self.tree_role,
            "file_count": self.file_count,
            "directory_count": self.directory_count,
            "total_size": self.total_size,
            "files": [item.to_dict() for item in self.files],
        }

    def to_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_dict(),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, data: bytes) -> "SealedExecutionTreeManifest":
        if not isinstance(data, bytes) or not data or len(data) > MAX_MANIFEST_BYTES:
            raise R002FSealedExecutionTreeError(
                "sealed execution manifest size is outside bounds"
            )

        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in items:
                if key in result:
                    raise R002FSealedExecutionTreeError(
                        "sealed execution manifest contains duplicate fields"
                    )
                result[key] = value
            return result

        try:
            raw = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise R002FSealedExecutionTreeError(
                "sealed execution manifest must be strict UTF-8 JSON"
            ) from exc
        if not isinstance(raw, dict):
            raise R002FSealedExecutionTreeError(
                "sealed execution manifest must be an object"
            )
        required = frozenset(
            {
                "schema_version",
                "reviewed_commit",
                "tree_role",
                "file_count",
                "directory_count",
                "total_size",
                "files",
            }
        )
        schema = raw.get("schema_version")
        if (
            frozenset(raw) != required
            or not isinstance(schema, int)
            or isinstance(schema, bool)
            or schema != SCHEMA_VERSION
        ):
            raise R002FSealedExecutionTreeError(
                "sealed execution manifest fields/schema are invalid"
            )
        files_raw = raw.get("files")
        if not isinstance(files_raw, list):
            raise R002FSealedExecutionTreeError(
                "sealed execution manifest files must be a list"
            )
        reviewed_commit = raw.get("reviewed_commit")
        role = raw.get("tree_role")
        file_count = raw.get("file_count")
        directory_count = raw.get("directory_count")
        total_size = raw.get("total_size")
        if (
            not isinstance(reviewed_commit, str)
            or not isinstance(role, str)
            or not isinstance(file_count, int)
            or isinstance(file_count, bool)
            or not isinstance(directory_count, int)
            or isinstance(directory_count, bool)
            or not isinstance(total_size, int)
            or isinstance(total_size, bool)
        ):
            raise R002FSealedExecutionTreeError(
                "sealed execution manifest field types are invalid"
            )
        manifest = cls(
            reviewed_commit=reviewed_commit,
            tree_role=role,
            file_count=file_count,
            directory_count=directory_count,
            total_size=total_size,
            files=tuple(
                SealedExecutionFile.from_mapping(item)
                if isinstance(item, dict)
                else (_ for _ in ()).throw(
                    R002FSealedExecutionTreeError(
                        "sealed execution manifest file entry is invalid"
                    )
                )
                for item in files_raw
            ),
        )
        manifest.validate()
        return manifest


def build_reviewed_project_manifest(
    root: Path,
    *,
    reviewed_commit: str,
    expected_git_blobs: Mapping[str, str],
) -> SealedExecutionTreeManifest:
    commit = _sha1(reviewed_commit, "reviewed commit")
    if not isinstance(expected_git_blobs, Mapping) or not expected_git_blobs:
        raise R002FSealedExecutionTreeError("expected Git blob mapping is required")

    expected: dict[str, str] = {}
    folded: set[str] = set()
    for raw_path, raw_blob in expected_git_blobs.items():
        path = _relative(raw_path)
        key = path.casefold()
        if key in folded:
            raise R002FSealedExecutionTreeError(
                "expected Git tree contains duplicate/case-colliding paths"
            )
        folded.add(key)
        expected[path] = _sha1(raw_blob, "expected Git blob SHA-1")

    authority = _resolve_package_root(root)
    actual_paths = _iter_package_files(authority)
    actual = {path.relative_to(authority).as_posix(): path for path in actual_paths}
    if set(actual) != set(expected):
        raise R002FSealedExecutionTreeError(
            "sealed execution source tree differs from externally reviewed Git tree"
        )
    directories = _implied_directories(set(expected))
    if _actual_directories(authority) != directories:
        raise R002FSealedExecutionTreeError(
            "sealed execution source directory namespace differs from reviewed tree"
        )

    files: list[SealedExecutionFile] = []
    total = 0
    for relative in sorted(expected, key=lambda value: (value.casefold(), value)):
        data = _read(actual[relative])
        if _git_blob_sha1(data) != expected[relative]:
            raise R002FSealedExecutionTreeError(
                f"sealed execution source bytes differ from reviewed Git blob: {relative}"
            )
        total += len(data)
        if total > MAX_TREE_BYTES:
            raise R002FSealedExecutionTreeError(
                "sealed execution tree total size exceeds safety bound"
            )
        files.append(
            SealedExecutionFile(
                path=relative,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                git_blob_sha1=expected[relative],
            )
        )

    manifest = SealedExecutionTreeManifest(
        reviewed_commit=commit,
        tree_role=TREE_ROLE_REVIEWED_PROJECT,
        file_count=len(files),
        directory_count=len(directories),
        total_size=total,
        files=tuple(files),
    )
    manifest.validate()
    return manifest


def verify_sealed_execution_tree(
    root: Path,
    manifest: SealedExecutionTreeManifest,
) -> None:
    if not isinstance(manifest, SealedExecutionTreeManifest):
        raise TypeError("manifest must be SealedExecutionTreeManifest")
    manifest.validate()
    authority = _resolve_package_root(root)
    actual_paths = _iter_package_files(authority)
    actual = {path.relative_to(authority).as_posix(): path for path in actual_paths}
    expected = {item.path: item for item in manifest.files}
    if set(actual) != set(expected):
        raise R002FSealedExecutionTreeError(
            "sealed execution tree differs from manifest"
        )
    if _actual_directories(authority) != _implied_directories(set(expected)):
        raise R002FSealedExecutionTreeError(
            "sealed execution directory namespace differs from manifest"
        )

    total = 0
    for relative, item in expected.items():
        data = _read(actual[relative])
        if len(data) != item.size:
            raise R002FSealedExecutionTreeError(
                f"sealed execution file size differs: {relative}"
            )
        if hashlib.sha256(data).hexdigest() != item.sha256:
            raise R002FSealedExecutionTreeError(
                f"sealed execution file SHA-256 differs: {relative}"
            )
        if _git_blob_sha1(data) != item.git_blob_sha1:
            raise R002FSealedExecutionTreeError(
                f"sealed execution Git blob differs: {relative}"
            )
        total += len(data)
    if len(actual) != manifest.file_count or total != manifest.total_size:
        raise R002FSealedExecutionTreeError(
            "sealed execution aggregate metadata differs"
        )
