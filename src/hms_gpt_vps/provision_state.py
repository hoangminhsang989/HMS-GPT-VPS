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
        data = dict(payload)
        data["state"] = ProvisionState(data["state"])
        if data.get("resume_state") is not None:
            data["resume_state"] = ProvisionState(data["resume_state"])
        return cls(**data)


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


class ProvisionStateStore:
    SCHEMA_VERSION = 1

    def __init__(self, path: Path) -> None:
        # Do not resolve: resolving could canonicalize away symlink/reparse
        # evidence before the authority-path gate observes it.
        self.path = path.expanduser().absolute()

    def _assert_safe_authority_path(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise ValueError("provision state authority path traverses a link or reparse point")
        if self.path.exists() and not self.path.is_file():
            raise ValueError("provision state authority path is not a regular file")

    def load(self) -> ProvisionRecord | None:
        self._assert_safe_authority_path()
        if not self.path.exists():
            return None
        size = self.path.stat().st_size
        if size <= 0 or size > _MAX_PROVISION_STATE_BYTES:
            raise ValueError("provision state size is outside supported bounds")
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("provision state must be a JSON object")
        record = ProvisionRecord.from_dict(raw)
        if record.schema_version != self.SCHEMA_VERSION:
            raise ValueError(f"unsupported provision state schema: {record.schema_version}")
        if not isinstance(record.instance_id, str) or not record.instance_id.strip():
            raise ValueError("provision state instance_id is invalid")
        if not isinstance(record.attempt, int) or isinstance(record.attempt, bool) or record.attempt < 0:
            raise ValueError("provision state attempt is invalid")
        return record

    def save(self, record: ProvisionRecord) -> None:
        if record.schema_version != self.SCHEMA_VERSION:
            raise ValueError("record schema does not match store schema")
        if not isinstance(record.instance_id, str) or not record.instance_id.strip():
            raise ValueError("record instance_id is invalid")
        if not isinstance(record.attempt, int) or isinstance(record.attempt, bool) or record.attempt < 0:
            raise ValueError("record attempt is invalid")

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
            if temp_path is not None:
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
