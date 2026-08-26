from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import secrets
import shutil
import stat
from tempfile import mkdtemp
from typing import Callable
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from zipfile import ZipFile, ZipInfo

from .qualification_file_authority import lexical_absolute, path_chain_has_redirect, read_file_pinned, write_bytes_create_only
from .secure_mcp_tunnel import OPENAI_TUNNEL_CLIENT_ASSET, OPENAI_TUNNEL_CLIENT_ASSET_SIZE, OPENAI_TUNNEL_CLIENT_SHA256, TunnelClientPackagePin

OPENAI_TUNNEL_CLIENT_RELEASE_URL = (
    "https://github.com/openai/tunnel-client/releases/download/v0.0.12/"
    "tunnel-client-runtime-v0.0.12-windows-amd64.zip"
)

_MAX_ARCHIVE = 16 * 1024 * 1024
_MAX_FILE = 32 * 1024 * 1024
_MAX_TOTAL = 48 * 1024 * 1024
_STAGE_MARKER = ".hms-openai-tunnel-stage-owned"

def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()

def _pkg():
    from . import secure_mcp_tunnel_package as package
    return package

def _read_verified_archive_bytes(path: Path) -> bytes:
    pin = TunnelClientPackagePin(); pin.validate()
    authority = lexical_absolute(path)
    if authority.name != pin.asset_name:
        raise _pkg().TunnelRuntimePackageError("OpenAI tunnel-client archive filename differs from pinned authority")
    raw = read_file_pinned(authority, max_bytes=_MAX_ARCHIVE, label="OpenAI tunnel-client archive")
    if len(raw) != pin.asset_size or not secrets.compare_digest(_sha(raw), pin.sha256):
        raise _pkg().TunnelRuntimePackageError("OpenAI tunnel-client archive differs from pinned authority")
    return raw


def _validate_zip_info(info: ZipInfo) -> None:
    if info.filename not in _pkg().EXPECTED_RUNTIME_ARCHIVE_FILES or Path(info.filename).name != info.filename:
        raise _pkg().TunnelRuntimePackageError("tunnel runtime ZIP member path differs")
    if info.is_dir() or not 0 < info.file_size <= _MAX_FILE or info.flag_bits & 1:
        raise _pkg().TunnelRuntimePackageError("tunnel runtime ZIP member is invalid or encrypted")
    if info.create_system == 3:
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFREG):
            raise _pkg().TunnelRuntimePackageError("tunnel runtime ZIP member is not a regular file")


def manifest_from_verified_archive_bytes(raw: bytes) -> object:
    if len(raw) != OPENAI_TUNNEL_CLIENT_ASSET_SIZE or not secrets.compare_digest(_sha(raw), OPENAI_TUNNEL_CLIENT_SHA256):
        raise _pkg().TunnelRuntimePackageError("verified tunnel archive bytes differ from release pin")
    records = []
    with ZipFile(BytesIO(raw), "r") as archive:
        infos = archive.infolist()
        if len(infos) != len(_pkg().EXPECTED_RUNTIME_ARCHIVE_FILES) or frozenset(i.filename for i in infos) != _pkg().EXPECTED_RUNTIME_ARCHIVE_FILES:
            raise _pkg().TunnelRuntimePackageError("tunnel runtime ZIP exact member set differs")
        total = 0
        for info in infos:
            _validate_zip_info(info); total += info.file_size
            if total > _MAX_TOTAL: raise _pkg().TunnelRuntimePackageError("tunnel runtime ZIP exceeds total safety bound")
            data = archive.read(info)
            if len(data) != info.file_size: raise _pkg().TunnelRuntimePackageError("tunnel runtime ZIP member size changed")
            records.append(_pkg().TunnelRuntimeFileRecord(info.filename, len(data), _sha(data)))
    manifest = _pkg().TunnelRuntimePackageManifest(tuple(sorted(records, key=lambda r: r.name))); manifest.validate(); return manifest


def acquire_official_tunnel_archive(target: Path, *, opener: Callable = urlopen) -> str:
    target = lexical_absolute(target)
    if target.name != OPENAI_TUNNEL_CLIENT_ASSET or target.exists() or path_chain_has_redirect(target.parent) or not target.parent.is_dir():
        raise FileExistsError("tunnel archive target is not a new stable official-asset path")
    request = Request(OPENAI_TUNNEL_CLIENT_RELEASE_URL, headers={"User-Agent":"HMS-GPT-VPS tunnel provisioner/1"})
    response = opener(request, timeout=60)
    try:
        final = urlsplit(response.geturl())
        if final.scheme != "https": raise _pkg().TunnelRuntimePackageError("tunnel archive redirect escaped HTTPS")
        length = response.headers.get("Content-Length")
        if length is not None and int(length) != OPENAI_TUNNEL_CLIENT_ASSET_SIZE:
            raise _pkg().TunnelRuntimePackageError("tunnel archive Content-Length differs")
        raw = response.read(OPENAI_TUNNEL_CLIENT_ASSET_SIZE + 1)
    finally: response.close()
    if len(raw) != OPENAI_TUNNEL_CLIENT_ASSET_SIZE or _sha(raw) != OPENAI_TUNNEL_CLIENT_SHA256:
        raise _pkg().TunnelRuntimePackageError("downloaded tunnel archive differs from release pin")
    write_bytes_create_only(target, raw, max_bytes=_MAX_ARCHIVE, label="OpenAI tunnel-client archive")
    _read_verified_archive_bytes(target); return OPENAI_TUNNEL_CLIENT_SHA256


def extract_verified_tunnel_archive(archive_path: Path, target: Path) -> object:
    target = lexical_absolute(target)
    if target.exists() or path_chain_has_redirect(target.parent) or not target.parent.is_dir():
        raise FileExistsError("tunnel install target is not new or stable")
    raw = _read_verified_archive_bytes(archive_path); manifest = manifest_from_verified_archive_bytes(raw)
    stage = Path(mkdtemp(prefix=".hms-tunnel-", dir=target.parent)); marker = stage / _STAGE_MARKER
    marker.write_text("owned\n", encoding="ascii")
    try:
        with ZipFile(BytesIO(raw), "r") as zf:
            for record in manifest.files:
                info = zf.getinfo(record.name); _validate_zip_info(info); data = zf.read(info)
                write_bytes_create_only(stage / record.name, data, max_bytes=_MAX_FILE, label=f"tunnel runtime {record.name}")
        for record in manifest.files:
            if _sha(read_file_pinned(stage/record.name,max_bytes=_MAX_FILE,label=record.name)) != record.sha256:
                raise _pkg().TunnelRuntimePackageError("extracted tunnel runtime file differs from verified archive")
        marker.unlink(); os.rename(stage, target)
    except BaseException:
        if stage.exists() and not marker.exists(): marker.write_text("owned\n", encoding="ascii")
        if stage.exists() and marker.is_file() and not path_chain_has_redirect(stage): shutil.rmtree(stage)
        raise
    return manifest
