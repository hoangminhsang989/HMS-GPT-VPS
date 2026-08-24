from __future__ import annotations

import json
from dataclasses import asdict, dataclass
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
import uuid

from .authority_lock import exclusive_authority_lock


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_INSTANCE_REGISTRY_BYTES = 1024 * 1024
_VM_RECORD_REQUIRED_FIELDS = frozenset(
    {
        "instance_id",
        "vm_name",
        "backend",
        "phase",
        "workspace_path",
    }
)
_VM_RECORD_OPTIONAL_FIELDS = frozenset(
    {
        "vm_id",
        "switch_name",
        "guest_ipv4",
    }
)
_VM_RECORD_FIELDS = _VM_RECORD_REQUIRED_FIELDS | _VM_RECORD_OPTIONAL_FIELDS


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"registry {label} must be a non-empty string")
    return value


def _require_optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, label)


def _require_optional_vm_id(value: object) -> str | None:
    if value is None:
        return None
    vm_id = _require_text(value, "vm_id")
    try:
        canonical = str(uuid.UUID(vm_id))
    except (ValueError, AttributeError) as exc:
        raise ValueError("registry vm_id must be a canonical GUID") from exc
    if vm_id != canonical:
        raise ValueError("registry vm_id must use canonical lowercase GUID form")
    return canonical


def _path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = path.expanduser().absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            return True
        try:
            stat_result = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = int(getattr(stat_result, "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    return False


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


@dataclass(frozen=True)
class VMRecord:
    instance_id: str
    vm_name: str
    backend: str
    phase: str
    workspace_path: str
    vm_id: str | None = None
    switch_name: str | None = None
    guest_ipv4: str | None = None

    def validate(self) -> None:
        _require_text(self.instance_id, "instance_id")
        _require_text(self.vm_name, "vm_name")
        _require_text(self.backend, "backend")
        _require_text(self.phase, "phase")
        _require_text(self.workspace_path, "workspace_path")
        _require_optional_vm_id(self.vm_id)
        _require_optional_text(self.switch_name, "switch_name")
        _require_optional_text(self.guest_ipv4, "guest_ipv4")

    @classmethod
    def from_mapping(cls, raw: object) -> "VMRecord":
        if not isinstance(raw, dict):
            raise ValueError("registry VM record must be an object")
        keys = frozenset(raw.keys())
        if not _VM_RECORD_REQUIRED_FIELDS.issubset(keys) or not keys.issubset(
            _VM_RECORD_FIELDS
        ):
            raise ValueError("registry VM record fields are invalid")
        record = cls(
            instance_id=_require_text(raw["instance_id"], "instance_id"),
            vm_name=_require_text(raw["vm_name"], "vm_name"),
            backend=_require_text(raw["backend"], "backend"),
            phase=_require_text(raw["phase"], "phase"),
            workspace_path=_require_text(raw["workspace_path"], "workspace_path"),
            vm_id=_require_optional_vm_id(raw.get("vm_id")),
            switch_name=_require_optional_text(raw.get("switch_name"), "switch_name"),
            guest_ipv4=_require_optional_text(raw.get("guest_ipv4"), "guest_ipv4"),
        )
        record.validate()
        return record


class InstanceRegistry:
    def __init__(self, path: Path) -> None:
        # Keep lexical authority; resolving would erase symlink/junction evidence.
        self.path = path.expanduser().absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    def _assert_safe_authority_path(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise ValueError("instance registry authority path traverses a link or reparse point")
        parent = self.path.parent
        if parent.exists() and not parent.is_dir():
            raise ValueError("instance registry parent authority is not a directory")
        if self.path.exists() and not self.path.is_file():
            raise ValueError("instance registry authority path is not a regular file")

    def _prepare_authority_parent(self) -> None:
        self._assert_safe_authority_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._assert_safe_authority_path()
        if not self.path.parent.is_dir():
            raise ValueError("instance registry parent authority is not a directory")

    def _load_unlocked(self) -> dict[str, VMRecord]:
        self._assert_safe_authority_path()
        if not self.path.exists():
            return {}

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        fd: int | None = None
        try:
            fd = os.open(self.path, flags)
            opened_stat = os.fstat(fd)
            if opened_stat.st_size <= 0 or opened_stat.st_size > _MAX_INSTANCE_REGISTRY_BYTES:
                raise ValueError("instance registry size is outside supported bounds")
            self._assert_safe_authority_path()
            current_stat = self.path.stat()
            if not _same_file_identity(opened_stat, current_stat):
                raise ValueError("instance registry authority changed during open")
            with os.fdopen(fd, "rb", closefd=True) as handle:
                fd = None
                raw_bytes = handle.read(_MAX_INSTANCE_REGISTRY_BYTES + 1)
            self._assert_safe_authority_path()
            current_stat = self.path.stat()
            if not _same_file_identity(opened_stat, current_stat):
                raise ValueError("instance registry authority changed during read")
            if len(raw_bytes) != opened_stat.st_size:
                raise ValueError("instance registry changed during read")
        finally:
            if fd is not None:
                os.close(fd)

        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("instance registry is not valid UTF-8 JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("registry root must be an object")

        records: dict[str, VMRecord] = {}
        for key, raw in data.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("registry instance key must be a non-empty string")
            record = VMRecord.from_mapping(raw)
            if record.instance_id != key:
                raise ValueError("registry key does not match VM record instance_id")
            records[key] = record
        return records

    def load(self) -> dict[str, VMRecord]:
        # Atomic replacement means an unlocked reader observes either the prior
        # complete registry or the next complete registry. All cooperating
        # writers serialize and re-read the latest registry under lock.
        return self._load_unlocked()

    def get(self, instance_id: str) -> VMRecord | None:
        _require_text(instance_id, "lookup instance_id")
        return self.load().get(instance_id)

    def _write_records_unlocked(self, records: dict[str, VMRecord]) -> None:
        self._prepare_authority_parent()
        for key, value in records.items():
            _require_text(key, "instance key")
            value.validate()
            if value.instance_id != key:
                raise ValueError("registry key does not match VM record instance_id")

        payload = {key: asdict(value) for key, value in sorted(records.items())}
        encoded = (
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        if len(encoded) > _MAX_INSTANCE_REGISTRY_BYTES:
            raise ValueError("instance registry exceeds supported size")

        temp_path: Path | None = None
        try:
            with NamedTemporaryFile(
                "wb",
                dir=self.path.parent,
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
                temp_path = Path(handle.name)
            self._assert_safe_authority_path()
            temp_path.replace(self.path)
            self._assert_safe_authority_path()
        finally:
            if temp_path is not None and not _path_chain_has_redirect(temp_path):
                temp_path.unlink(missing_ok=True)

    def upsert(self, record: VMRecord) -> None:
        record.validate()
        self._prepare_authority_parent()
        with exclusive_authority_lock(self.lock_path):
            # Re-read inside the writer lock. This prevents two host processes
            # from loading the same snapshot and then replacing each other's
            # unrelated records or stale VM identity evidence.
            records = self._load_unlocked()
            existing = records.get(record.instance_id)
            if (
                existing is not None
                and existing.vm_id is not None
                and record.vm_id is not None
                and existing.vm_id != record.vm_id
            ):
                raise ValueError("refusing to replace persisted VM identity with a different VMId")
            records[record.instance_id] = record
            self._write_records_unlocked(records)
