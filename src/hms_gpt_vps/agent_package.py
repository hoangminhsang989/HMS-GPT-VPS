from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .windows_image import sha256_file


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
            "filename": self.filename,
            "version": self.version,
            "size": self.size,
            "sha256": self.sha256.lower(),
        }


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
