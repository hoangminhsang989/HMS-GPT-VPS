from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


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


class ProvisionStateStore:
    SCHEMA_VERSION = 1

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> ProvisionRecord | None:
        if not self.path.exists():
            return None
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("provision state must be a JSON object")
        record = ProvisionRecord.from_dict(raw)
        if record.schema_version != self.SCHEMA_VERSION:
            raise ValueError(f"unsupported provision state schema: {record.schema_version}")
        return record

    def save(self, record: ProvisionRecord) -> None:
        if record.schema_version != self.SCHEMA_VERSION:
            raise ValueError("record schema does not match store schema")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.path.parent,
            prefix=self.path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(record.to_dict(), handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            temp_path = Path(handle.name)
        temp_path.replace(self.path)

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
