from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping

from .agent_package import (
    AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION,
    AGENT_PACKAGE_PLATFORM,
    MAX_AGENT_MANIFEST_BYTES,
    MAX_AGENT_PACKAGE_BYTES,
    MAX_AGENT_PACKAGE_FILES,
    AgentPackageFile,
    _iter_package_files,
    _resolve_package_root,
    _validate_relative_package_path,
    require_windows_amd64_pe,
)
from .windows_image import sha256_file


BRIDGE_PACKAGE_MANIFEST_SCHEMA_VERSION = AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION
BRIDGE_PACKAGE_PLATFORM = AGENT_PACKAGE_PLATFORM
BRIDGE_PACKAGE_ENTRYPOINT = "hms-bridge.exe"
MAX_BRIDGE_MANIFEST_BYTES = MAX_AGENT_MANIFEST_BYTES
MAX_BRIDGE_PACKAGE_FILES = MAX_AGENT_PACKAGE_FILES
MAX_BRIDGE_PACKAGE_BYTES = MAX_AGENT_PACKAGE_BYTES


@dataclass(frozen=True)
class BridgePackageManifest:
    """Immutable integrity metadata for a complete HMSBridge Windows onedir tree."""

    platform: str
    version: str
    entrypoint: str
    file_count: int
    total_size: int
    files: tuple[AgentPackageFile, ...]

    def validate(self) -> None:
        if self.platform != BRIDGE_PACKAGE_PLATFORM:
            raise ValueError("Bridge package platform must be windows-x64")
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("Bridge package version is required")
        if self.entrypoint != BRIDGE_PACKAGE_ENTRYPOINT:
            raise ValueError("Bridge package entrypoint must be hms-bridge.exe")
        if not isinstance(self.file_count, int) or isinstance(self.file_count, bool):
            raise ValueError("Bridge package file_count must be an integer")
        if not isinstance(self.total_size, int) or isinstance(self.total_size, bool):
            raise ValueError("Bridge package total_size must be an integer")
        if not 1 <= self.file_count <= MAX_BRIDGE_PACKAGE_FILES:
            raise ValueError("Bridge package file_count is outside safety bounds")
        if not 1 <= self.total_size <= MAX_BRIDGE_PACKAGE_BYTES:
            raise ValueError("Bridge package total_size is outside safety bounds")
        if len(self.files) != self.file_count:
            raise ValueError("Bridge package file_count does not match files")

        seen: set[str] = set()
        ordered: list[str] = []
        total = 0
        for item in self.files:
            item.validate()
            folded = item.path.casefold()
            if folded in seen:
                raise ValueError("Bridge package contains duplicate/case-colliding paths")
            seen.add(folded)
            ordered.append(item.path)
            total += item.size
        if ordered != sorted(ordered, key=lambda value: (value.casefold(), value)):
            raise ValueError("Bridge package files must be deterministically sorted")
        if self.entrypoint.casefold() not in seen:
            raise ValueError("Bridge package entrypoint is absent from files")
        if total != self.total_size:
            raise ValueError("Bridge package total_size does not match files")

    @property
    def entrypoint_file(self) -> AgentPackageFile:
        self.validate()
        for item in self.files:
            if item.path.casefold() == self.entrypoint.casefold():
                return item
        raise ValueError("Bridge package entrypoint is absent")

    @property
    def sha256(self) -> str:
        return self.entrypoint_file.sha256

    @property
    def size(self) -> int:
        return self.entrypoint_file.size

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": BRIDGE_PACKAGE_MANIFEST_SCHEMA_VERSION,
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
    def from_mapping(cls, raw: Mapping[str, object]) -> "BridgePackageManifest":
        required = frozenset(
            {
                "schema_version",
                "platform",
                "version",
                "entrypoint",
                "file_count",
                "total_size",
                "files",
            }
        )
        if frozenset(raw.keys()) != required:
            raise ValueError("Bridge package manifest fields are invalid")
        version_number = raw["schema_version"]
        if (
            not isinstance(version_number, int)
            or isinstance(version_number, bool)
            or version_number != BRIDGE_PACKAGE_MANIFEST_SCHEMA_VERSION
        ):
            raise ValueError("Bridge package manifest schema_version is invalid")
        platform = raw["platform"]
        version = raw["version"]
        entrypoint = raw["entrypoint"]
        file_count = raw["file_count"]
        total_size = raw["total_size"]
        files_raw = raw["files"]
        if not all(isinstance(value, str) for value in (platform, version, entrypoint)):
            raise ValueError("Bridge package manifest text fields must be strings")
        if not isinstance(file_count, int) or isinstance(file_count, bool):
            raise ValueError("Bridge package manifest file_count must be an integer")
        if not isinstance(total_size, int) or isinstance(total_size, bool):
            raise ValueError("Bridge package manifest total_size must be an integer")
        if not isinstance(files_raw, list):
            raise ValueError("Bridge package manifest files must be a list")
        files: list[AgentPackageFile] = []
        for item in files_raw:
            if not isinstance(item, dict):
                raise ValueError("Bridge package file entries must be objects")
            files.append(AgentPackageFile.from_mapping(item))
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


def build_bridge_package_manifest(root: Path, *, version: str) -> BridgePackageManifest:
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
            raise ValueError("Bridge package contains duplicate/case-colliding paths")
        seen.add(folded)
        size = path.stat().st_size
        if size <= 0:
            raise ValueError("Bridge package files must not be empty")
        total += size
        if total > MAX_BRIDGE_PACKAGE_BYTES:
            raise ValueError("Bridge package total size exceeds safety bound")
        items.append(
            AgentPackageFile(
                path=relative,
                size=size,
                sha256=sha256_file(path).lower(),
            )
        )
    items.sort(key=lambda item: (item.path.casefold(), item.path))
    manifest = BridgePackageManifest(
        platform=BRIDGE_PACKAGE_PLATFORM,
        version=version,
        entrypoint=BRIDGE_PACKAGE_ENTRYPOINT,
        file_count=len(items),
        total_size=total,
        files=tuple(items),
    )
    manifest.validate()
    return manifest


def verify_bridge_package(root: Path, manifest: BridgePackageManifest) -> None:
    manifest.validate()
    root = _resolve_package_root(root)
    actual_paths = _iter_package_files(root)
    actual: dict[str, Path] = {}
    for path in actual_paths:
        relative = path.relative_to(root).as_posix()
        _validate_relative_package_path(relative)
        folded = relative.casefold()
        if folded in actual:
            raise ValueError("Bridge package contains duplicate/case-colliding paths")
        actual[folded] = path

    expected = {item.path.casefold(): item for item in manifest.files}
    if set(actual) != set(expected):
        raise ValueError("Bridge package tree differs from manifest")

    total = 0
    for folded, item in expected.items():
        path = actual[folded]
        relative = path.relative_to(root).as_posix()
        if relative != item.path:
            raise ValueError("Bridge package path casing differs from manifest")
        size = path.stat().st_size
        if size != item.size:
            raise ValueError(f"Bridge package file size mismatch: {item.path}")
        if sha256_file(path).lower() != item.sha256.lower():
            raise ValueError(f"Bridge package file SHA-256 mismatch: {item.path}")
        total += size
    if len(actual_paths) != manifest.file_count or total != manifest.total_size:
        raise ValueError("Bridge package aggregate metadata mismatch")


def write_bridge_package_manifest(
    path: Path,
    manifest: BridgePackageManifest,
) -> None:
    manifest.validate()
    if not path.is_absolute():
        path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (manifest.to_json() + "\n").encode("utf-8")
    if len(data) > MAX_BRIDGE_MANIFEST_BYTES:
        raise ValueError("Bridge package manifest is too large")
    temp = path.with_name(path.name + ".tmp")
    temp.write_bytes(data)
    temp.replace(path)


def load_bridge_package_manifest(path: Path) -> BridgePackageManifest:
    if not path.is_file():
        raise FileNotFoundError(path)
    data = path.read_bytes()
    if not data or len(data) > MAX_BRIDGE_MANIFEST_BYTES:
        raise ValueError("Bridge package manifest size is outside supported bounds")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in items:
            if key in out:
                raise ValueError("Bridge package manifest contains duplicate fields")
            out[key] = value
        return out

    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Bridge package manifest must be valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("Bridge package manifest must be a JSON object")
    return BridgePackageManifest.from_mapping(raw)


def require_bridge_windows_amd64_pe(path: Path) -> None:
    if path.name.casefold() != BRIDGE_PACKAGE_ENTRYPOINT:
        raise ValueError("Bridge package PE authority must be hms-bridge.exe")
    require_windows_amd64_pe(path)
