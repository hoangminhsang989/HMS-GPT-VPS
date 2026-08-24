from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping

from .windows_image import sha256_file


AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION = 1
WINDOWS_AMD64_MACHINE = 0x8664
MAX_AGENT_MANIFEST_BYTES = 16 * 1024


@dataclass(frozen=True)
class AgentPackageManifest:
    """Non-secret immutable metadata for one HMS Agent executable artifact."""

    filename: str
    version: str
    size: int
    sha256: str

    def validate(self) -> None:
        if not self.filename.strip():
            raise ValueError("agent filename is required")
        if Path(self.filename).name != self.filename:
            raise ValueError("agent filename must not contain a path")
        if not self.filename.lower().endswith(".exe"):
            raise ValueError("Windows agent artifact must be an .exe")
        if not self.version.strip():
            raise ValueError("agent version is required")
        if self.size <= 0:
            raise ValueError("agent size must be positive")
        if len(self.sha256) != 64:
            raise ValueError("agent SHA-256 must contain 64 hex characters")
        try:
            int(self.sha256, 16)
        except ValueError as exc:
            raise ValueError("agent SHA-256 must be hexadecimal") from exc

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION,
            "filename": self.filename,
            "version": self.version,
            "size": self.size,
            "sha256": self.sha256.lower(),
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
        required = frozenset({"schema_version", "filename", "version", "size", "sha256"})
        keys = frozenset(raw.keys())
        if keys != required:
            missing = sorted(required - keys)
            unknown = sorted(keys - required)
            detail: list[str] = []
            if missing:
                detail.append("missing=" + ",".join(missing))
            if unknown:
                detail.append("unknown=" + ",".join(unknown))
            raise ValueError("agent manifest fields are invalid: " + "; ".join(detail))

        schema_version = raw["schema_version"]
        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise ValueError("agent manifest schema_version must be an integer")
        if schema_version != AGENT_PACKAGE_MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported Agent package manifest schema_version")

        filename = raw["filename"]
        version = raw["version"]
        size = raw["size"]
        sha256 = raw["sha256"]
        if not isinstance(filename, str):
            raise ValueError("agent manifest filename must be a string")
        if not isinstance(version, str):
            raise ValueError("agent manifest version must be a string")
        if not isinstance(size, int) or isinstance(size, bool):
            raise ValueError("agent manifest size must be an integer")
        if not isinstance(sha256, str):
            raise ValueError("agent manifest sha256 must be a string")

        manifest = cls(
            filename=filename,
            version=version,
            size=size,
            sha256=sha256,
        )
        manifest.validate()
        return manifest


def build_agent_package_manifest(path: Path, *, version: str) -> AgentPackageManifest:
    """Build deterministic integrity metadata for a local agent executable."""
    if not path.is_file():
        raise FileNotFoundError(path)
    manifest = AgentPackageManifest(
        filename=path.name,
        version=version,
        size=path.stat().st_size,
        sha256=sha256_file(path).lower(),
    )
    manifest.validate()
    return manifest


def verify_agent_package(path: Path, manifest: AgentPackageManifest) -> None:
    """Fail closed when the artifact differs from the approved manifest."""
    manifest.validate()
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.name != manifest.filename:
        raise ValueError("agent filename does not match manifest")
    if path.stat().st_size != manifest.size:
        raise ValueError("agent size does not match manifest")
    if sha256_file(path).lower() != manifest.sha256.lower():
        raise ValueError("agent SHA-256 does not match manifest")


def require_windows_amd64_pe(path: Path) -> None:
    """Require a native Windows PE executable targeting AMD64.

    This is an artifact-shape gate, not a signature/authenticity check. The
    immutable SHA-256 manifest remains the artifact identity authority.
    """
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
        signature = handle.read(4)
        if signature != b"PE\x00\x00":
            raise ValueError("Agent artifact has an invalid PE signature")
        machine_bytes = handle.read(2)
        if len(machine_bytes) != 2:
            raise ValueError("Agent artifact PE machine field is truncated")
        machine = int.from_bytes(machine_bytes, "little")
        if machine != WINDOWS_AMD64_MACHINE:
            raise ValueError(
                f"Agent artifact must target Windows AMD64 (machine=0x{machine:04x})"
            )


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
