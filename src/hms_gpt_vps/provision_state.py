from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_PROVISION_STATE_BYTES = 64 * 1024
_PROVISION_REQUIRED_FIELDS = frozenset({"schema_version", "instance_id", "state"})
_PROVISION_OPTIONAL_FIELDS = frozenset(
    {"attempt", "reason", "resume_state", "last_error"}
)
_PROVISION_FIELDS = _PROVISION_REQUIRED_FIELDS | _PROVISION_OPTIONAL_FIELDS


class ProvisionState(str, Enum):
    IDLE = "idle"
    PREFLIGHT = "preflight"
    NEED_ELEVATION = "need_elevation"
    REBOOT_PENDING = "reboot_pending"
    IMAGE_READY = "image_ready"
    NETWORK_READY = "network_ready"
    VM_CREATED = "vm_created"
    INSTALL_MEDIA_READY = "install_media_ready"
    OS_INSTALLING = "os_installing"
    GUEST_BOOTED = "guest_booted"
    GUEST_BOOTSTRAP = "guest_bootstrap"
    AGENT_INSTALLING = "agent_installing"
    AGENT_SERVICE_READY = "agent_service_ready"
    AGENT_HEALTHY = "agent_healthy"
    BOOTSTRAP_RETIRING = "bootstrap_retiring"
    BOOTSTRAP_RETIRED = "bootstrap_retired"
    ANSWER_MEDIA_DETACHED = "answer_media_detached"
    INSTALL_SECRETS_CLEARED = "install_secrets_cleared"
    PAIRING_PENDING = "pairing_pending"
    READY = "ready"
    FAILED = "failed"


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"provision state {label} must be a string or null")
    return value


@dataclass(frozen=True)
class ProvisionRecord:
    schema_version: int
    instance_id: str
    state: ProvisionState
    attempt: int = 0
    reason: str | None = None
    resume_state: ProvisionState | None = None
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload["resume_state"] = self.resume_state.value if self.resume_state else None
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ProvisionRecord":
        keys = frozenset(payload.keys())
        if not _PROVISION_REQUIRED_FIELDS.issubset(keys) or not keys.issubset(
            _PROVISION_FIELDS
        ):
            raise ValueError("provision state fields are invalid")
        schema_version = payload["schema_version"]
        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise ValueError("provision state schema_version must be an integer")
        instance_id = payload["instance_id"]
        if not isinstance(instance_id, str) or not instance_id.strip():
            raise ValueError("provision state instance_id is invalid")
        state_raw = payload["state"]
        if not isinstance(state_raw, str):
            raise ValueError("provision state state must be a string")
        attempt = payload.get("attempt", 0)
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 0:
            raise ValueError("provision state attempt is invalid")
        reason = _optional_text(payload.get("reason"), "reason")
        last_error = _optional_text(payload.get("last_error"), "last_error")
        resume_raw = payload.get("resume_state")
        if resume_raw is not None and not isinstance(resume_raw, str):
            raise ValueError("provision state resume_state must be a string or null")
        try:
            state = ProvisionState(state_raw)
            resume_state = ProvisionState(resume_raw) if resume_raw is not None else None
        except ValueError as exc:
            raise ValueError("provision state enum value is invalid") from exc
        return cls(
            schema_version=schema_version,
            instance_id=instance_id,
            state=state,
            attempt=attempt,
            reason=reason,
            resume_state=resume_state,
            last_error=last_error,
        )


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


class ProvisionStateStore:
    SCHEMA_VERSION = 1

    def __init__(self, path: Path) -> None:
        # Do not resolve: resolving could canonicalize away symlink/reparse
        # evidence before the authority-path gate observes it.
        self.path = path.expanduser().absolute()

    def _assert_safe_authority_path(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise ValueError("provision state authority path traverses a link or reparse point")
        if self.path.parent.exists() and not self.path.parent.is_dir():
            raise ValueError("provision state parent authority is not a directory")
        if self.path.exists() and not self.path.is_file():
            raise ValueError("provision state authority path is not a regular file")

    def load(self) -> ProvisionRecord | None:
        self._assert_safe_authority_path()
        if not self.path.exists():
            return None

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        fd: int | None = None
        try:
            fd = os.open(self.path, flags)
            opened_stat = os.fstat(fd)
            if opened_stat.st_size <= 0 or opened_stat.st_size > _MAX_PROVISION_STATE_BYTES:
                raise ValueError("provision state size is outside supported bounds")
            self._assert_safe_authority_path()
            current_stat = self.path.stat()
            if not _same_file_identity(opened_stat, current_stat):
                raise ValueError("provision state authority changed during open")
            with os.fdopen(fd, "rb", closefd=True) as handle:
                fd = None
                raw_bytes = handle.read(_MAX_PROVISION_STATE_BYTES + 1)
            self._assert_safe_authority_path()
            current_stat = self.path.stat()
            if not _same_file_identity(opened_stat, current_stat):
                raise ValueError("provision state authority changed during read")
            if len(raw_bytes) != opened_stat.st_size:
                raise ValueError("provision state changed during read")
        finally:
            if fd is not None:
                os.close(fd)

        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("provision state is not valid UTF-8 JSON") from exc
        if not isinstance(raw, dict):
            raise ValueError("provision state must be a JSON object")
        record = ProvisionRecord.from_dict(raw)
        if record.schema_version != self.SCHEMA_VERSION:
            raise ValueError(f"unsupported provision state schema: {record.schema_version}")
        return record

    def save(self, record: ProvisionRecord) -> None:
        if (
            not isinstance(record.schema_version, int)
            or isinstance(record.schema_version, bool)
            or record.schema_version != self.SCHEMA_VERSION
        ):
            raise ValueError("record schema does not match store schema")
        if not isinstance(record.instance_id, str) or not record.instance_id.strip():
            raise ValueError("record instance_id is invalid")
        if not isinstance(record.state, ProvisionState):
            raise ValueError("record state is invalid")
        if not isinstance(record.attempt, int) or isinstance(record.attempt, bool) or record.attempt < 0:
            raise ValueError("record attempt is invalid")
        _optional_text(record.reason, "reason")
        _optional_text(record.last_error, "last_error")
        if record.resume_state is not None and not isinstance(record.resume_state, ProvisionState):
            raise ValueError("record resume_state is invalid")

        # Gate existing ancestors before creating anything, then verify again
        # after mkdir so an existing redirect is never silently traversed.
        self._assert_safe_authority_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._assert_safe_authority_path()
        if not self.path.parent.is_dir():
            raise ValueError("provision state parent is not a directory")

        payload = json.dumps(
            record.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        ) + "\n"
        encoded = payload.encode("utf-8")
        if len(encoded) > _MAX_PROVISION_STATE_BYTES:
            raise ValueError("provision state exceeds supported size")

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

    def transition(
        self,
        *,
        instance_id: str,
        state: ProvisionState,
        reason: str | None = None,
        resume_state: ProvisionState | None = None,
        last_error: str | None = None,
        increment_attempt: bool = False,
    ) -> ProvisionRecord:
        current = self.load()
        if current is not None and current.instance_id != instance_id:
            raise ValueError("provision state belongs to another instance")
        attempt = current.attempt if current else 0
        if increment_attempt:
            attempt += 1
        record = ProvisionRecord(
            schema_version=self.SCHEMA_VERSION,
            instance_id=instance_id,
            state=state,
            attempt=attempt,
            reason=reason,
            resume_state=resume_state,
            last_error=last_error,
        )
        self.save(record)
        return record

    def transition_checked(
        self,
        *,
        instance_id: str,
        expected_state: ProvisionState,
        state: ProvisionState,
        reason: str | None = None,
        last_error: str | None = None,
    ) -> ProvisionRecord:
        """Advance only from the exact persisted checkpoint expected by caller."""
        current = self.load()
        if current is None:
            raise ValueError("provision state does not exist")
        if current.instance_id != instance_id:
            raise ValueError("provision state belongs to another instance")
        if current.state is not expected_state:
            raise ValueError(
                f"expected provision state {expected_state.value}, found {current.state.value}"
            )
        return self.transition(
            instance_id=instance_id,
            state=state,
            reason=reason,
            last_error=last_error,
        )
