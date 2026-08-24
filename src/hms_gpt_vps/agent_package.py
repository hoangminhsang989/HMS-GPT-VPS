from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from .windows_image import sha256_file


AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION = 2
AGENT_PACKAGE_PLATFORM = "windows-x64"
AGENT_PACKAGE_ENTRYPOINT = "hms-agent.exe"
WINDOWS_AMD64_MACHINE = 0x8664
MAX_AGENT_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_AGENT_PACKAGE_FILES = 4096
MAX_AGENT_PACKAGE_BYTES = 1024 * 1024 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_WINDOWS_FORBIDDEN_NAME_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


def _validate_sha256(value: str, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{label} SHA-256 must contain 64 hex characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{label} SHA-256 must be hexadecimal") from exc
    return value.lower()


def _validate_relative_package_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Agent package file path is required")
    if "\\" in value:
        raise ValueError("Agent package paths must use forward slashes")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value:
        raise ValueError("Agent package file path must be canonical and relative")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Agent package file path contains unsafe traversal")
    for part in path.parts:
        if part.endswith((" ", ".")):
            raise ValueError("Agent package file path is unsafe on Windows")
        if any(char in _WINDOWS_FORBIDDEN_NAME_CHARS for char in part):
            raise ValueError("Agent package file path contains unsupported Windows characters")
        stem = part.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise ValueError("Agent package file path uses a reserved Windows name")
    return value


def _is_reparse_point(path: Path) -> bool:
    stat_result = path.lstat()
    attributes = int(getattr(stat_result, "st_file_attributes", 0))
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _resolve_package_root(root: Path) -> Path:
    """Reject a linked root before resolution can erase the trust-boundary fact."""
    root.lstat()
    if root.is_symlink() or _is_reparse_point(root):
        raise ValueError("Agent package root must not be a link or reparse point")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise FileNotFoundError(root)
    return resolved


def _iter_package_files(root: Path) -> list[Path]:
    if not root.is_dir():
        raise FileNotFoundError(root)
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if current_path != root and (current_path.is_symlink() or _is_reparse_point(current_path)):
            raise ValueError("Agent package must not contain directory links or reparse points")
        for dirname in dirnames:
            directory = current_path / dirname
            if directory.is_symlink() or _is_reparse_point(directory):
                raise ValueError("Agent package must not contain directory links or reparse points")
        for filename in filenames:
            file_path = current_path / filename
            if file_path.is_symlink() or _is_reparse_point(file_path):
                raise ValueError("Agent package must not contain file links or reparse points")
            if not file_path.is_file():
                raise ValueError("Agent package contains a non-regular file")
            files.append(file_path)
            if len(files) > MAX_AGENT_PACKAGE_FILES:
                raise ValueError("Agent package file count exceeds safety bound")
    return files


@dataclass(frozen=True)
class AgentPackageFile:
    path: str
    size: int
    sha256: str

    def validate(self) -> None:
        _validate_relative_package_path(self.path)
        if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size <= 0:
            raise ValueError("Agent package file size must be a positive integer")
        _validate_sha256(self.sha256, label="Agent package file")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {"path": self.path, "size": self.size, "sha256": self.sha256.lower()}

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> "AgentPackageFile":
        required = frozenset({"path", "size", "sha256"})
        if frozenset(raw.keys()) != required:
            raise ValueError("Agent package file manifest fields are invalid")
        path = raw["path"]
        size = raw["size"]
        sha256 = raw["sha256"]
        if not isinstance(path, str):
            raise ValueError("Agent package file path must be a string")
        if not isinstance(size, int) or isinstance(size, bool):
            raise ValueError("Agent package file size must be an integer")
        if not isinstance(sha256, str):
            raise ValueError("Agent package file sha256 must be a string")
        item = cls(path=path, size=size, sha256=sha256)
        item.validate()
        return item


@dataclass(frozen=True)
class AgentPackageManifest:
    """Immutable, complete integrity metadata for an HMS Agent onedir tree."""

    platform: str
    version: str
    entrypoint: str
    file_count: int
    total_size: int
    files: tuple[AgentPackageFile, ...]

    def validate(self) -> None:
        if self.platform != AGENT_PACKAGE_PLATFORM:
            raise ValueError("Agent package platform must be windows-x64")
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("Agent version is required")
        if self.entrypoint != AGENT_PACKAGE_ENTRYPOINT:
            raise ValueError("Agent package entrypoint must be hms-agent.exe")
        if not isinstance(self.file_count, int) or isinstance(self.file_count, bool):
            raise ValueError("Agent package file_count must be an integer")
        if not isinstance(self.total_size, int) or isinstance(self.total_size, bool):
            raise ValueError("Agent package total_size must be an integer")
        if not 1 <= self.file_count <= MAX_AGENT_PACKAGE_FILES:
            raise ValueError("Agent package file_count is outside safety bounds")
        if not 1 <= self.total_size <= MAX_AGENT_PACKAGE_BYTES:
            raise ValueError("Agent package total_size is outside safety bounds")
        if len(self.files) != self.file_count:
            raise ValueError("Agent package file_count does not match files")

        seen: set[str] = set()
        normalized_paths: list[str] = []
        total = 0
        for item in self.files:
            item.validate()
            folded = item.path.casefold()
            if folded in seen:
                raise ValueError("Agent package contains duplicate/case-colliding paths")
            seen.add(folded)
            normalized_paths.append(item.path)
            total += item.size
        if normalized_paths != sorted(normalized_paths, key=lambda value: (value.casefold(), value)):
            raise ValueError("Agent package files must be deterministically sorted")
        if self.entrypoint.casefold() not in seen:
            raise ValueError("Agent package entrypoint is absent from files")
        if total != self.total_size:
            raise ValueError("Agent package total_size does not match files")

    @property
    def entrypoint_file(self) -> AgentPackageFile:
        self.validate()
        for item in self.files:
            if item.path.casefold() == self.entrypoint.casefold():
                return item
        raise ValueError("Agent package entrypoint is absent")

    @property
    def sha256(self) -> str:
        """Compatibility alias for callers that need the entrypoint identity."""
        return self.entrypoint_file.sha256

    @property
    def size(self) -> int:
        """Compatibility alias for callers that need the entrypoint size."""
        return self.entrypoint_file.size

    @property
    def filename(self) -> str:
        """Compatibility alias for the legacy single-file manifest API."""
        return self.entrypoint

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION,
            "platform": self.platform,
            "version": self.version,
            "entrypoint": self.entrypoint,
            "file_count": self.file_count,
            "total_size": self.total_size,
            "files": [item.to_dict() for item in self.files],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> "AgentPackageManifest":
        required = frozenset(
            {"schema_version", "platform", "version", "entrypoint", "file_count", "total_size", "files"}
        )
        keys = frozenset(raw.keys())
        if keys != required:
            missing = sorted(required - keys)
            unknown = sorted(keys - required)
            details: list[str] = []
            if missing:
                details.append("missing=" + ",".join(missing))
            if unknown:
                details.append("unknown=" + ",".join(unknown))
            raise ValueError("agent manifest fields are invalid: " + "; ".join(details))
        schema_version = raw["schema_version"]
        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise ValueError("agent manifest schema_version must be an integer")
        if schema_version != AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported Agent package manifest schema_version")

        platform = raw["platform"]
        version = raw["version"]
        entrypoint = raw["entrypoint"]
        file_count = raw["file_count"]
        total_size = raw["total_size"]
        files_raw = raw["files"]
        if not isinstance(platform, str) or not isinstance(version, str) or not isinstance(entrypoint, str):
            raise ValueError("Agent manifest text fields must be strings")
        if not isinstance(file_count, int) or isinstance(file_count, bool):
            raise ValueError("Agent manifest file_count must be an integer")
        if not isinstance(total_size, int) or isinstance(total_size, bool):
            raise ValueError("Agent manifest total_size must be an integer")
        if not isinstance(files_raw, list):
            raise ValueError("Agent manifest files must be a list")
        files: list[AgentPackageFile] = []
        for raw_item in files_raw:
            if not isinstance(raw_item, dict):
                raise ValueError("Agent manifest file entries must be objects")
            files.append(AgentPackageFile.from_mapping(raw_item))
        manifest = cls(
            platform=platform,
            version=version,
            entrypoint=entrypoint,
            file_count=file_count,
            total_size=total_size,
            files=tuple(files),
        )
        manifest.validate()
        return manifest


def build_agent_package_manifest(root: Path, *, version: str) -> AgentPackageManifest:
    """Build deterministic integrity metadata for a complete onedir package."""
    root = _resolve_package_root(root)
    paths = _iter_package_files(root)
    items: list[AgentPackageFile] = []
    total = 0
    seen: set[str] = set()
    for path in paths:
        relative = path.relative_to(root).as_posix()
        _validate_relative_package_path(relative)
        folded = relative.casefold()
        if folded in seen:
            raise ValueError("Agent package contains duplicate/case-colliding paths")
        seen.add(folded)
        size = path.stat().st_size
        if size <= 0:
            raise ValueError("Agent package files must not be empty")
        total += size
        if total > MAX_AGENT_PACKAGE_BYTES:
            raise ValueError("Agent package total size exceeds safety bound")
        items.append(AgentPackageFile(path=relative, size=size, sha256=sha256_file(path).lower()))
    items.sort(key=lambda item: (item.path.casefold(), item.path))
    manifest = AgentPackageManifest(
        platform=AGENT_PACKAGE_PLATFORM,
        version=version,
        entrypoint=AGENT_PACKAGE_ENTRYPOINT,
        file_count=len(items),
        total_size=total,
        files=tuple(items),
    )
    manifest.validate()
    return manifest


def verify_agent_package(root: Path, manifest: AgentPackageManifest) -> None:
    """Fail closed unless the complete package tree exactly matches its manifest."""
    manifest.validate()
    root = _resolve_package_root(root)
    actual_paths = _iter_package_files(root)
    actual_by_folded: dict[str, Path] = {}
    for path in actual_paths:
        relative = path.relative_to(root).as_posix()
        _validate_relative_package_path(relative)
        folded = relative.casefold()
        if folded in actual_by_folded:
            raise ValueError("Agent package contains duplicate/case-colliding paths")
        actual_by_folded[folded] = path

    expected_by_folded = {item.path.casefold(): item for item in manifest.files}
    if set(actual_by_folded) != set(expected_by_folded):
        missing = sorted(set(expected_by_folded) - set(actual_by_folded))
        extra = sorted(set(actual_by_folded) - set(expected_by_folded))
        detail: list[str] = []
        if missing:
            detail.append("missing=" + ",".join(missing[:8]))
        if extra:
            detail.append("extra=" + ",".join(extra[:8]))
        raise ValueError("Agent package tree differs from manifest: " + "; ".join(detail))

    total = 0
    for folded, item in expected_by_folded.items():
        path = actual_by_folded[folded]
        relative = path.relative_to(root).as_posix()
        if relative != item.path:
            raise ValueError("Agent package path casing differs from manifest")
        size = path.stat().st_size
        if size != item.size:
            raise ValueError(f"Agent package file size mismatch: {item.path}")
        if sha256_file(path).lower() != item.sha256.lower():
            raise ValueError(f"Agent package file SHA-256 mismatch: {item.path}")
        total += size
    if len(actual_paths) != manifest.file_count or total != manifest.total_size:
        raise ValueError("Agent package aggregate metadata mismatch")


def require_windows_amd64_pe(path: Path) -> None:
    """Require a native Windows PE executable targeting AMD64."""
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.suffix.lower() != ".exe":
        raise ValueError("Agent artifact must use the .exe suffix")
    with path.open("rb") as handle:
        dos_header = handle.read(64)
        if len(dos_header) < 64 or dos_header[:2] != b"MZ":
            raise ValueError("Agent artifact is not a Windows PE executable")
        pe_offset = int.from_bytes(dos_header[0x3C:0x40], "little")
        if pe_offset < 64 or pe_offset > path.stat().st_size - 6:
            raise ValueError("Agent PE header offset is outside artifact bounds")
        handle.seek(pe_offset)
        if handle.read(4) != b"PE\x00\x00":
            raise ValueError("Agent artifact has an invalid PE signature")
        machine_bytes = handle.read(2)
        if len(machine_bytes) != 2:
            raise ValueError("Agent artifact PE machine field is truncated")
        machine = int.from_bytes(machine_bytes, "little")
        if machine != WINDOWS_AMD64_MACHINE:
            raise ValueError(f"Agent artifact must target Windows AMD64 (machine=0x{machine:04x})")


def write_agent_package_manifest(path: Path, manifest: AgentPackageManifest) -> None:
    manifest.validate()
    if not path.is_absolute():
        path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (manifest.to_json() + "\n").encode("utf-8")
    if len(data) > MAX_AGENT_MANIFEST_BYTES:
        raise ValueError("Agent package manifest is too large")
    temp = path.with_name(path.name + ".tmp")
    temp.write_bytes(data)
    temp.replace(path)


def load_agent_package_manifest(path: Path) -> AgentPackageManifest:
    if not path.is_file():
        raise FileNotFoundError(path)
    data = path.read_bytes()
    if not data or len(data) > MAX_AGENT_MANIFEST_BYTES:
        raise ValueError("Agent package manifest size is outside supported bounds")
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Agent package manifest must be valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("Agent package manifest must be a JSON object")
    return AgentPackageManifest.from_mapping(raw)
