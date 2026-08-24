from __future__ import annotations

import hashlib
from pathlib import PureWindowsPath

from .agent_package import AgentPackageManifest, MAX_AGENT_MANIFEST_BYTES


AGENT_PACKAGE_MANIFEST_FILENAME = "hms-agent.manifest.json"


def canonical_agent_package_manifest_bytes(manifest: AgentPackageManifest) -> bytes:
    """Return the one canonical byte representation published with an Agent package."""
    manifest.validate()
    data = (manifest.to_json() + "\n").encode("utf-8")
    if not data or len(data) > MAX_AGENT_MANIFEST_BYTES:
        raise ValueError("Agent package manifest size is outside supported bounds")
    return data


def canonical_agent_package_manifest_sha256(manifest: AgentPackageManifest) -> str:
    return hashlib.sha256(canonical_agent_package_manifest_bytes(manifest)).hexdigest()


def canonical_agent_package_manifest_size(manifest: AgentPackageManifest) -> int:
    return len(canonical_agent_package_manifest_bytes(manifest))


def managed_agent_package_manifest_path(agent_root_path: str) -> str:
    root = PureWindowsPath(agent_root_path)
    if not root.is_absolute():
        raise ValueError("Agent root path must be absolute")
    return str(root / AGENT_PACKAGE_MANIFEST_FILENAME)
