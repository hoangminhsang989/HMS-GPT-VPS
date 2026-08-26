from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath

from .bridge_service_identity import require_hms_bridge_service_sid
from .bridge_service_provisioning_identity import prove_hms_bridge_provisioning_identity
from .qualification_file_authority import (
    lexical_absolute,
    path_chain_has_redirect,
    read_file_pinned,
    write_bytes_create_only,
)
from .secure_mcp_tunnel import (
    OPENAI_TUNNEL_CLIENT_ASSET,
    OPENAI_TUNNEL_CLIENT_ASSET_SIZE,
    OPENAI_TUNNEL_CLIENT_EXECUTABLE,
    OPENAI_TUNNEL_CLIENT_SHA256,
    OPENAI_TUNNEL_CLIENT_VERSION,
    TunnelClientPackagePin,
)

OPENAI_TUNNEL_CLIENT_RELEASE_URL = (
    "https://github.com/openai/tunnel-client/releases/download/v0.0.12/"
    "tunnel-client-runtime-v0.0.12-windows-amd64.zip"
)
OPENAI_TUNNEL_CLIENT_LICENSE_REPORT = "tunnel-client-runtime-v0.0.12-windows-amd64-licenses.txt"
OPENAI_TUNNEL_CLIENT_SBOM = "tunnel-client-runtime-v0.0.12-windows-amd64.spdx.json"
EXPECTED_RUNTIME_ARCHIVE_FILES = frozenset({
    OPENAI_TUNNEL_CLIENT_EXECUTABLE, "LICENSE", "NOTICE",
    OPENAI_TUNNEL_CLIENT_LICENSE_REPORT, OPENAI_TUNNEL_CLIENT_SBOM,
})
DEFAULT_TUNNEL_PACKAGE_ROOT = Path(r"C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client")
DEFAULT_TUNNEL_INSTALL_ROOT = DEFAULT_TUNNEL_PACKAGE_ROOT / "v0.0.12"
DEFAULT_TUNNEL_PACKAGE_MANIFEST_PATH = DEFAULT_TUNNEL_PACKAGE_ROOT / "hms-tunnel-runtime.manifest.json"
_MAX_ARCHIVE = 16 * 1024 * 1024
_MAX_FILE = 32 * 1024 * 1024
_MAX_TOTAL = 48 * 1024 * 1024
_MAX_MANIFEST = 16 * 1024
_STAGE_MARKER = ".hms-openai-tunnel-stage-owned"


class TunnelRuntimePackageError(RuntimeError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and value == value.lower() and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True)
class TunnelRuntimeFileRecord:
    name: str
    size: int
    sha256: str

    def validate(self) -> None:
        if self.name not in EXPECTED_RUNTIME_ARCHIVE_FILES:
            raise TunnelRuntimePackageError("tunnel runtime manifest contains an unknown file")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or not 0 < self.size <= _MAX_FILE:
            raise TunnelRuntimePackageError("tunnel runtime manifest file size is invalid")
        if not _canonical_hex(self.sha256):
            raise TunnelRuntimePackageError("tunnel runtime manifest SHA-256 is invalid")

    def to_dict(self) -> dict[str, object]:
        self.validate(); return {"name": self.name, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class TunnelRuntimePackageManifest:
    files: tuple[TunnelRuntimeFileRecord, ...]
    schema_version: int = 1
    upstream_version: str = OPENAI_TUNNEL_CLIENT_VERSION
    archive_name: str = OPENAI_TUNNEL_CLIENT_ASSET
    archive_size: int = OPENAI_TUNNEL_CLIENT_ASSET_SIZE
    archive_sha256: str = OPENAI_TUNNEL_CLIENT_SHA256

    def validate(self) -> None:
        if isinstance(self.schema_version, bool) or self.schema_version != 1:
            raise TunnelRuntimePackageError("tunnel runtime manifest schema differs")
        if (self.upstream_version, self.archive_name, self.archive_size, self.archive_sha256) != (
            OPENAI_TUNNEL_CLIENT_VERSION, OPENAI_TUNNEL_CLIENT_ASSET,
            OPENAI_TUNNEL_CLIENT_ASSET_SIZE, OPENAI_TUNNEL_CLIENT_SHA256,
        ):
            raise TunnelRuntimePackageError("tunnel runtime manifest upstream authority differs")
        if not isinstance(self.files, tuple) or len(self.files) != len(EXPECTED_RUNTIME_ARCHIVE_FILES):
            raise TunnelRuntimePackageError("tunnel runtime manifest file count differs")
        names = []
        for record in self.files:
            if not isinstance(record, TunnelRuntimeFileRecord):
                raise TunnelRuntimePackageError("tunnel runtime manifest file record is invalid")
            record.validate(); names.append(record.name)
        if len(names) != len(set(names)) or frozenset(names) != EXPECTED_RUNTIME_ARCHIVE_FILES:
            raise TunnelRuntimePackageError("tunnel runtime manifest exact file set differs")

    def to_json(self) -> str:
        self.validate()
        return json.dumps({
            "schema_version": self.schema_version, "upstream_version": self.upstream_version,
            "archive_name": self.archive_name, "archive_size": self.archive_size,
            "archive_sha256": self.archive_sha256, "files": [r.to_dict() for r in self.files],
        }, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "TunnelRuntimePackageManifest":
        def no_dupes(pairs):
            out = {}
            for key, value in pairs:
                if key in out: raise TunnelRuntimePackageError("tunnel runtime manifest JSON has duplicate keys")
                out[key] = value
            return out
        try: payload = json.loads(raw, object_pairs_hook=no_dupes)
        except TunnelRuntimePackageError: raise
        except Exception as exc: raise TunnelRuntimePackageError("tunnel runtime manifest JSON is invalid") from exc
        keys = {"schema_version","upstream_version","archive_name","archive_size","archive_sha256","files"}
        if not isinstance(payload, dict) or set(payload) != keys or not isinstance(payload["files"], list):
            raise TunnelRuntimePackageError("tunnel runtime manifest JSON shape differs")
        records = []
        for item in payload["files"]:
            if not isinstance(item, dict) or set(item) != {"name","size","sha256"}:
                raise TunnelRuntimePackageError("tunnel runtime manifest file entry shape differs")
            record = TunnelRuntimeFileRecord(item["name"], item["size"], item["sha256"])
            record.validate(); records.append(record)
        manifest = cls(tuple(records), payload["schema_version"], payload["upstream_version"], payload["archive_name"], payload["archive_size"], payload["archive_sha256"])
        manifest.validate(); return manifest


@dataclass(frozen=True)
class TunnelRuntimePackageConfig:
    package_root: Path = DEFAULT_TUNNEL_PACKAGE_ROOT
    install_root: Path = DEFAULT_TUNNEL_INSTALL_ROOT
    manifest_path: Path = DEFAULT_TUNNEL_PACKAGE_MANIFEST_PATH

    def validate(self) -> None:
        for value, expected, label in ((self.package_root,DEFAULT_TUNNEL_PACKAGE_ROOT,"package_root"),(self.install_root,DEFAULT_TUNNEL_INSTALL_ROOT,"install_root"),(self.manifest_path,DEFAULT_TUNNEL_PACKAGE_MANIFEST_PATH,"manifest_path")):
            if not isinstance(value, Path) or str(PureWindowsPath(str(value))).casefold() != str(PureWindowsPath(str(expected))).casefold():
                raise TunnelRuntimePackageError(f"{label} differs from fixed ProgramData authority")

    @property
    def executable_path(self) -> Path:
        return self.install_root / OPENAI_TUNNEL_CLIENT_EXECUTABLE


@dataclass(frozen=True)
class TunnelRuntimePackageEvidence:
    ready: bool
    created: bool
    package_root: str
    install_root: str
    manifest_path: str
    executable_path: str
    executable_sha256: str
    archive_sha256: str
    file_count: int


from .secure_mcp_tunnel_package_io import (
    _read_verified_archive_bytes, manifest_from_verified_archive_bytes,
    acquire_official_tunnel_archive, extract_verified_tunnel_archive,
)

def _canonical_manifest_bytes(manifest: TunnelRuntimePackageManifest) -> bytes:
    return (manifest.to_json() + "\n").encode()


def load_tunnel_runtime_package_manifest(path: Path) -> TunnelRuntimePackageManifest:
    raw = read_file_pinned(path, max_bytes=_MAX_MANIFEST, label="tunnel runtime package manifest")
    try: text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc: raise TunnelRuntimePackageError("tunnel runtime package manifest is not UTF-8") from exc
    return TunnelRuntimePackageManifest.from_json(text.rstrip("\n"))


def _prove_files_against_manifest(root: Path, manifest: TunnelRuntimePackageManifest) -> str:
    manifest.validate()
    if path_chain_has_redirect(root) or not root.is_dir(): raise TunnelRuntimePackageError("tunnel runtime install root is invalid")
    entries = list(root.iterdir())
    if frozenset(e.name for e in entries) != EXPECTED_RUNTIME_ARCHIVE_FILES or any(not e.is_file() or e.is_symlink() for e in entries):
        raise TunnelRuntimePackageError("tunnel runtime installed exact file set differs")
    digests = {}
    for record in manifest.files:
        data = read_file_pinned(root/record.name,max_bytes=_MAX_FILE,label=f"installed tunnel runtime {record.name}")
        if len(data) != record.size or _sha(data) != record.sha256: raise TunnelRuntimePackageError("installed tunnel runtime file differs from manifest")
        digests[record.name] = record.sha256
    return digests[OPENAI_TUNNEL_CLIENT_EXECUTABLE]


def prove_installed_tunnel_runtime(config: TunnelRuntimePackageConfig, *, service_sid: str, prove_acl: bool=True) -> TunnelRuntimePackageEvidence:
    config.validate(); require_hms_bridge_service_sid(service_sid)
    if prove_acl:
        from .secure_mcp_tunnel_package_acl import prove_tunnel_package_acls
        prove_tunnel_package_acls(config, service_sid=service_sid)
    manifest = load_tunnel_runtime_package_manifest(lexical_absolute(config.manifest_path))
    executable_hash = _prove_files_against_manifest(lexical_absolute(config.install_root), manifest)
    if prove_acl: prove_tunnel_package_acls(config, service_sid=service_sid)
    return TunnelRuntimePackageEvidence(True,False,str(config.package_root),str(config.install_root),str(config.manifest_path),str(config.executable_path),executable_hash,manifest.archive_sha256,len(manifest.files))


def provision_tunnel_runtime_package(archive: Path, config: TunnelRuntimePackageConfig|None=None) -> TunnelRuntimePackageEvidence:
    resolved = config or TunnelRuntimePackageConfig(); resolved.validate()
    identity = prove_hms_bridge_provisioning_identity(); sid = str(identity.get("service_sid")); require_hms_bridge_service_sid(sid)
    root = lexical_absolute(resolved.package_root)
    if path_chain_has_redirect(root.parent) or not root.parent.is_dir(): raise TunnelRuntimePackageError("Bridge host root is missing or redirected")
    if not root.exists(): os.mkdir(root)
    raw = _read_verified_archive_bytes(archive); expected = manifest_from_verified_archive_bytes(raw); created = False
    if not lexical_absolute(resolved.install_root).exists(): extract_verified_tunnel_archive(archive, lexical_absolute(resolved.install_root)); created=True
    else: _prove_files_against_manifest(lexical_absolute(resolved.install_root), expected)
    canonical = _canonical_manifest_bytes(expected)
    if lexical_absolute(resolved.manifest_path).exists():
        if load_tunnel_runtime_package_manifest(lexical_absolute(resolved.manifest_path)) != expected: raise TunnelRuntimePackageError("existing tunnel package manifest differs")
    else: write_bytes_create_only(lexical_absolute(resolved.manifest_path),canonical,max_bytes=_MAX_MANIFEST,label="tunnel runtime package manifest")
    from .secure_mcp_tunnel_package_acl import reconcile_tunnel_package_acls
    reconcile_tunnel_package_acls(resolved, service_sid=sid)
    evidence = prove_installed_tunnel_runtime(resolved, service_sid=sid)
    return TunnelRuntimePackageEvidence(**{**evidence.__dict__,"created":created})
