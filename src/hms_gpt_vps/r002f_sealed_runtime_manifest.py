from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Mapping

from .agent_package import _iter_package_files, _resolve_package_root, _validate_relative_package_path
from .qualification_file_authority import path_chain_has_redirect, read_file_pinned

SCHEMA_VERSION = 1
ROLE_PYTHON_RUNTIME = "python-runtime"
ROLE_GIT_RUNTIME = "git-runtime"
_ALLOWED_ROLES = frozenset({ROLE_PYTHON_RUNTIME, ROLE_GIT_RUNTIME})
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RUNTIME_FILES = 8192
MAX_RUNTIME_BYTES = 2 * 1024 * 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 512 * 1024 * 1024

class R002FSealedRuntimeError(RuntimeError):
    pass

def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower() or any(c not in "0123456789abcdef" for c in value):
        raise R002FSealedRuntimeError(f"{label} must be canonical lowercase SHA-256")
    return value

def _relative(value: object) -> str:
    if not isinstance(value, str):
        raise R002FSealedRuntimeError("sealed runtime path must be text")
    try:
        return _validate_relative_package_path(value)
    except ValueError as exc:
        raise R002FSealedRuntimeError(str(exc)) from exc

def _implied_directories(paths: tuple[str, ...] | set[str]) -> set[str]:
    result: set[str] = set()
    for relative in paths:
        parts = PurePosixPath(relative).parts[:-1]
        for index in range(1, len(parts) + 1):
            result.add("/".join(parts[:index]))
    return result

def _actual_directories(root: Path) -> set[str]:
    authority = _resolve_package_root(root)
    result: set[str] = set()
    for current_text, dirnames, _ in os.walk(authority, topdown=True, followlinks=False):
        current = Path(current_text)
        for dirname in dirnames:
            directory = current / dirname
            if path_chain_has_redirect(directory):
                raise R002FSealedRuntimeError("sealed runtime contains redirected directory")
            relative = directory.relative_to(authority).as_posix()
            _relative(relative)
            result.add(relative)
    return result

def _read(path: Path) -> bytes:
    return read_file_pinned(path, max_bytes=MAX_RUNTIME_FILE_BYTES, label="R002F sealed runtime file", allow_empty=True)

@dataclass(frozen=True)
class SealedRuntimeFile:
    path: str
    size: int
    sha256: str
    def validate(self) -> None:
        _relative(self.path)
        if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size < 0 or self.size > MAX_RUNTIME_FILE_BYTES:
            raise R002FSealedRuntimeError("sealed runtime file size is invalid")
        _sha256(self.sha256, "sealed runtime file SHA-256")
    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {"path": self.path, "size": self.size, "sha256": self.sha256}
    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> "SealedRuntimeFile":
        if frozenset(raw) != frozenset({"path","size","sha256"}):
            raise R002FSealedRuntimeError("sealed runtime file fields are invalid")
        path, size, sha256 = raw.get("path"), raw.get("size"), raw.get("sha256")
        if not isinstance(path, str) or not isinstance(size, int) or isinstance(size, bool) or not isinstance(sha256, str):
            raise R002FSealedRuntimeError("sealed runtime file field types are invalid")
        item = cls(path=path, size=size, sha256=sha256)
        item.validate()
        return item

@dataclass(frozen=True)
class SealedRuntimeManifest:
    runtime_role: str
    entrypoint: str
    file_count: int
    directory_count: int
    total_size: int
    files: tuple[SealedRuntimeFile, ...]
    def validate(self) -> None:
        if self.runtime_role not in _ALLOWED_ROLES:
            raise R002FSealedRuntimeError("sealed runtime role is invalid")
        entrypoint = _relative(self.entrypoint)
        wanted = "python.exe" if self.runtime_role == ROLE_PYTHON_RUNTIME else "git.exe"
        if PurePosixPath(entrypoint).name.casefold() != wanted:
            raise R002FSealedRuntimeError(f"sealed runtime entrypoint must be {wanted}")
        if not isinstance(self.file_count, int) or isinstance(self.file_count, bool) or not 1 <= self.file_count <= MAX_RUNTIME_FILES:
            raise R002FSealedRuntimeError("sealed runtime file_count is invalid")
        if not isinstance(self.directory_count, int) or isinstance(self.directory_count, bool) or not 0 <= self.directory_count <= MAX_RUNTIME_FILES:
            raise R002FSealedRuntimeError("sealed runtime directory_count is invalid")
        if not isinstance(self.total_size, int) or isinstance(self.total_size, bool) or not 0 <= self.total_size <= MAX_RUNTIME_BYTES:
            raise R002FSealedRuntimeError("sealed runtime total_size is invalid")
        if len(self.files) != self.file_count:
            raise R002FSealedRuntimeError("sealed runtime file_count does not match files")
        seen: set[str] = set()
        ordered: list[str] = []
        total = 0
        entrypoints = 0
        for item in self.files:
            item.validate()
            folded = item.path.casefold()
            if folded in seen:
                raise R002FSealedRuntimeError("sealed runtime contains duplicate/case-colliding paths")
            seen.add(folded); ordered.append(item.path); total += item.size
            if folded == entrypoint.casefold():
                entrypoints += 1
        if entrypoints != 1:
            raise R002FSealedRuntimeError("sealed runtime entrypoint is absent or ambiguous")
        if ordered != sorted(ordered, key=lambda v: (v.casefold(), v)):
            raise R002FSealedRuntimeError("sealed runtime files are not sorted")
        if len(_implied_directories(tuple(ordered))) != self.directory_count:
            raise R002FSealedRuntimeError("sealed runtime directory_count does not match file paths")
        if total != self.total_size:
            raise R002FSealedRuntimeError("sealed runtime total_size does not match files")
        if self.runtime_role == ROLE_GIT_RUNTIME:
            forbidden = {"powershell.exe","pwsh.exe","cmd.exe","python.exe"}
            if any(PurePosixPath(item.path).name.casefold() in forbidden for item in self.files):
                raise R002FSealedRuntimeError("Git runtime must not shadow OS/Python host executables")
    @property
    def entrypoint_file(self) -> SealedRuntimeFile:
        self.validate()
        for item in self.files:
            if item.path.casefold() == self.entrypoint.casefold():
                return item
        raise R002FSealedRuntimeError("sealed runtime entrypoint is absent")
    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {"schema_version":SCHEMA_VERSION,"runtime_role":self.runtime_role,"entrypoint":self.entrypoint,"file_count":self.file_count,"directory_count":self.directory_count,"total_size":self.total_size,"files":[item.to_dict() for item in self.files]}
    def to_bytes(self) -> bytes:
        return (json.dumps(self.to_dict(),ensure_ascii=True,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode("utf-8")
    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()
    @classmethod
    def from_bytes(cls, data: bytes) -> "SealedRuntimeManifest":
        if not isinstance(data, bytes) or not data or len(data) > MAX_MANIFEST_BYTES:
            raise R002FSealedRuntimeError("sealed runtime manifest size is outside bounds")
        def pairs(items):
            out={}
            for key,value in items:
                if key in out: raise R002FSealedRuntimeError("sealed runtime manifest contains duplicate fields")
                out[key]=value
            return out
        try:
            raw=json.loads(data.decode("utf-8"),object_pairs_hook=pairs)
        except (UnicodeDecodeError,json.JSONDecodeError) as exc:
            raise R002FSealedRuntimeError("sealed runtime manifest must be strict UTF-8 JSON") from exc
        required=frozenset({"schema_version","runtime_role","entrypoint","file_count","directory_count","total_size","files"})
        if not isinstance(raw,dict) or frozenset(raw)!=required or type(raw.get("schema_version")) is not int or raw.get("schema_version")!=SCHEMA_VERSION:
            raise R002FSealedRuntimeError("sealed runtime manifest fields/schema are invalid")
        files_raw=raw.get("files")
        if not isinstance(files_raw,list):
            raise R002FSealedRuntimeError("sealed runtime manifest files must be a list")
        role,entrypoint=raw.get("runtime_role"),raw.get("entrypoint")
        fc,dc,total=raw.get("file_count"),raw.get("directory_count"),raw.get("total_size")
        if not isinstance(role,str) or not isinstance(entrypoint,str) or type(fc) is not int or type(dc) is not int or type(total) is not int:
            raise R002FSealedRuntimeError("sealed runtime manifest field types are invalid")
        manifest=cls(runtime_role=role,entrypoint=entrypoint,file_count=fc,directory_count=dc,total_size=total,files=tuple(SealedRuntimeFile.from_mapping(i) if isinstance(i,dict) else (_ for _ in ()).throw(R002FSealedRuntimeError("sealed runtime manifest file entry is invalid")) for i in files_raw))
        manifest.validate()
        return manifest

def build_sealed_runtime_manifest(root: Path, *, runtime_role: str, entrypoint: str) -> SealedRuntimeManifest:
    authority=_resolve_package_root(root)
    relative_entrypoint=_relative(entrypoint)
    files=[]; total=0
    for path in _iter_package_files(authority):
        relative=path.relative_to(authority).as_posix(); _relative(relative)
        data=_read(path); total+=len(data)
        if total>MAX_RUNTIME_BYTES: raise R002FSealedRuntimeError("sealed runtime total size exceeds bound")
        files.append(SealedRuntimeFile(relative,len(data),hashlib.sha256(data).hexdigest()))
    files.sort(key=lambda i:(i.path.casefold(),i.path))
    implied=_implied_directories({i.path for i in files})
    if _actual_directories(authority)!=implied:
        raise R002FSealedRuntimeError("sealed runtime directory namespace contains extra entries")
    manifest=SealedRuntimeManifest(runtime_role,relative_entrypoint,len(files),len(implied),total,tuple(files))
    manifest.validate()
    return manifest

def verify_sealed_runtime_tree(root: Path, manifest: SealedRuntimeManifest) -> None:
    if not isinstance(manifest,SealedRuntimeManifest): raise TypeError("manifest must be SealedRuntimeManifest")
    manifest.validate(); authority=_resolve_package_root(root)
    actual_paths=_iter_package_files(authority)
    actual={p.relative_to(authority).as_posix():p for p in actual_paths}
    expected={i.path:i for i in manifest.files}
    if set(actual)!=set(expected): raise R002FSealedRuntimeError("sealed runtime tree differs from manifest")
    if _actual_directories(authority)!=_implied_directories(set(expected)):
        raise R002FSealedRuntimeError("sealed runtime directory namespace differs from manifest")
    total=0
    for relative,item in expected.items():
        data=_read(actual[relative])
        if len(data)!=item.size: raise R002FSealedRuntimeError(f"sealed runtime file size differs: {relative}")
        if hashlib.sha256(data).hexdigest()!=item.sha256: raise R002FSealedRuntimeError(f"sealed runtime file SHA-256 differs: {relative}")
        total+=len(data)
    if len(actual)!=manifest.file_count or total!=manifest.total_size:
        raise R002FSealedRuntimeError("sealed runtime aggregate metadata differs")
