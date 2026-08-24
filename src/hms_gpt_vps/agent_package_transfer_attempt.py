from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
import secrets
from tempfile import NamedTemporaryFile
import uuid

from .install_artifacts import TextSecretStore


AGENT_PACKAGE_TRANSFER_ATTEMPT_SCHEMA_VERSION = 1
_TRANSFER_ID_HEX_LENGTH = 32
_OWNERSHIP_TOKEN_HEX_LENGTH = 48


class AgentPackageTransferPhase(str, Enum):
    PLANNED = "planned"
    TRANSFERRING = "transferring"
    PUBLISHED = "published"


def _require_hex(value: str, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or value != value.lower():
        raise ValueError(f"{label} must contain exactly {length} lowercase hex characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{label} must be lowercase hexadecimal") from exc
    return value


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    return value


@dataclass(frozen=True)
class AgentPackageTransferAttempt:
    instance_id: str
    vm_name: str
    manifest_sha256: str
    transfer_id: str
    phase: AgentPackageTransferPhase
    guest_service_interface_was_enabled: bool | None
    ownership_token: str = field(repr=False, compare=False)

    def validate(self) -> None:
        _require_text(self.instance_id, "instance_id")
        _require_text(self.vm_name, "vm_name")
        _require_hex(self.manifest_sha256, 64, "manifest_sha256")
        _require_hex(self.transfer_id, _TRANSFER_ID_HEX_LENGTH, "transfer_id")
        _require_hex(
            self.ownership_token,
            _OWNERSHIP_TOKEN_HEX_LENGTH,
            "ownership_token",
        )
        if not isinstance(self.phase, AgentPackageTransferPhase):
            raise ValueError("phase is invalid")
        baseline = self.guest_service_interface_was_enabled
        if baseline is not None and not isinstance(baseline, bool):
            raise ValueError("Guest Service Interface baseline must be boolean or null")
        if self.phase is not AgentPackageTransferPhase.PLANNED and baseline is None:
            raise ValueError(
                "Guest Service Interface baseline is required before transfer mutation"
            )

    def metadata(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": AGENT_PACKAGE_TRANSFER_ATTEMPT_SCHEMA_VERSION,
            "instance_id": self.instance_id,
            "vm_name": self.vm_name,
            "manifest_sha256": self.manifest_sha256,
            "transfer_id": self.transfer_id,
            "phase": self.phase.value,
            "guest_service_interface_was_enabled": self.guest_service_interface_was_enabled,
        }


class AgentPackageTransferAttemptStore:
    """Crash-safe transfer metadata with destructive authority outside JSON.

    The ownership token that permits deletion of an interrupted guest staging
    root is stored only through the injected protected secret store. The durable
    JSON also captures the pre-transfer Hyper-V Guest Service Interface state so
    a retry can restore the exact host baseline after a process interruption.
    Missing/mismatching halves fail closed instead of generating replacement
    authority for an existing transfer id.
    """

    def __init__(self, metadata_path: Path, secret_store: TextSecretStore) -> None:
        self.metadata_path = metadata_path.expanduser().absolute()
        self.secret_store = secret_store

    def _write_metadata(self, attempt: AgentPackageTransferAttempt) -> None:
        payload = json.dumps(
            attempt.metadata(),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ) + "\n"
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.metadata_path.parent,
            prefix=self.metadata_path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(payload)
            handle.flush()
            temp = Path(handle.name)
        temp.replace(self.metadata_path)

    def load(self) -> AgentPackageTransferAttempt | None:
        if not self.metadata_path.exists():
            return None
        if not self.metadata_path.is_file() or self.metadata_path.is_symlink():
            raise ValueError("Agent package transfer attempt metadata path is unsafe")
        try:
            raw = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Agent package transfer attempt metadata is invalid") from exc
        if not isinstance(raw, dict):
            raise ValueError("Agent package transfer attempt metadata must be an object")
        required = {
            "schema_version",
            "instance_id",
            "vm_name",
            "manifest_sha256",
            "transfer_id",
            "phase",
            "guest_service_interface_was_enabled",
        }
        if set(raw) != required:
            raise ValueError("Agent package transfer attempt metadata fields are invalid")
        if raw["schema_version"] != AGENT_PACKAGE_TRANSFER_ATTEMPT_SCHEMA_VERSION:
            raise ValueError("unsupported Agent package transfer attempt schema")
        instance_id = _require_text(raw["instance_id"], "instance_id")
        vm_name = _require_text(raw["vm_name"], "vm_name")
        manifest_sha256 = raw["manifest_sha256"]
        transfer_id = raw["transfer_id"]
        phase_raw = raw["phase"]
        baseline = raw["guest_service_interface_was_enabled"]
        if not isinstance(manifest_sha256, str) or not isinstance(transfer_id, str):
            raise ValueError("Agent package transfer hash/id metadata types are invalid")
        if not isinstance(phase_raw, str):
            raise ValueError("Agent package transfer phase metadata type is invalid")
        if baseline is not None and not isinstance(baseline, bool):
            raise ValueError("Guest Service Interface baseline metadata type is invalid")
        try:
            token = self.secret_store.load_text()
        except FileNotFoundError as exc:
            raise ValueError("Agent package transfer ownership token is missing") from exc
        try:
            phase = AgentPackageTransferPhase(phase_raw)
        except ValueError as exc:
            raise ValueError("Agent package transfer attempt phase is invalid") from exc
        attempt = AgentPackageTransferAttempt(
            instance_id=instance_id,
            vm_name=vm_name,
            manifest_sha256=manifest_sha256,
            transfer_id=transfer_id,
            phase=phase,
            guest_service_interface_was_enabled=baseline,
            ownership_token=token,
        )
        attempt.validate()
        return attempt

    def begin_or_resume(
        self,
        *,
        instance_id: str,
        vm_name: str,
        manifest_sha256: str,
    ) -> AgentPackageTransferAttempt:
        _require_text(instance_id, "instance_id")
        _require_text(vm_name, "vm_name")
        _require_hex(manifest_sha256, 64, "manifest_sha256")
        existing = self.load()
        if existing is not None:
            if existing.instance_id != instance_id:
                raise ValueError("transfer attempt belongs to another instance")
            if existing.vm_name != vm_name:
                raise ValueError("transfer attempt belongs to another VM")
            if existing.manifest_sha256 != manifest_sha256:
                raise ValueError("transfer attempt belongs to another package manifest")
            return existing

        token = secrets.token_hex(24)
        attempt = AgentPackageTransferAttempt(
            instance_id=instance_id,
            vm_name=vm_name,
            manifest_sha256=manifest_sha256,
            transfer_id=uuid.uuid4().hex,
            phase=AgentPackageTransferPhase.PLANNED,
            guest_service_interface_was_enabled=None,
            ownership_token=token,
        )
        attempt.validate()
        # Secret first: a crash here leaves only an orphan secret, which cannot
        # authorize guest cleanup because no transfer id has been persisted.
        self.secret_store.save_text(token)
        try:
            self._write_metadata(attempt)
        except Exception:
            self.secret_store.clear()
            raise
        return attempt

    def bind_guest_service_interface_baseline(
        self,
        was_enabled: bool,
    ) -> AgentPackageTransferAttempt:
        if not isinstance(was_enabled, bool):
            raise TypeError("Guest Service Interface baseline must be boolean")
        current = self.load()
        if current is None:
            raise ValueError("Agent package transfer attempt does not exist")
        if current.phase is not AgentPackageTransferPhase.PLANNED:
            if current.guest_service_interface_was_enabled is was_enabled:
                return current
            raise ValueError("cannot change Guest Service Interface baseline after mutation")
        if current.guest_service_interface_was_enabled is not None:
            if current.guest_service_interface_was_enabled is not was_enabled:
                raise ValueError("Guest Service Interface baseline conflicts with persisted value")
            return current
        updated = AgentPackageTransferAttempt(
            instance_id=current.instance_id,
            vm_name=current.vm_name,
            manifest_sha256=current.manifest_sha256,
            transfer_id=current.transfer_id,
            phase=current.phase,
            guest_service_interface_was_enabled=was_enabled,
            ownership_token=current.ownership_token,
        )
        self._write_metadata(updated)
        return updated

    def transition(
        self,
        expected: AgentPackageTransferPhase,
        target: AgentPackageTransferPhase,
    ) -> AgentPackageTransferAttempt:
        current = self.load()
        if current is None:
            raise ValueError("Agent package transfer attempt does not exist")
        if current.phase is not expected:
            raise ValueError(
                f"expected transfer phase {expected.value}, found {current.phase.value}"
            )
        if target is not AgentPackageTransferPhase.PLANNED and (
            current.guest_service_interface_was_enabled is None
        ):
            raise ValueError(
                "Guest Service Interface baseline must be persisted before transfer mutation"
            )
        updated = AgentPackageTransferAttempt(
            instance_id=current.instance_id,
            vm_name=current.vm_name,
            manifest_sha256=current.manifest_sha256,
            transfer_id=current.transfer_id,
            phase=target,
            guest_service_interface_was_enabled=current.guest_service_interface_was_enabled,
            ownership_token=current.ownership_token,
        )
        self._write_metadata(updated)
        return updated

    def clear_published(self) -> None:
        current = self.load()
        if current is None:
            return
        if current.phase is not AgentPackageTransferPhase.PUBLISHED:
            raise ValueError("only a published transfer attempt may be cleared")
        # Metadata first: a crash can leave an orphan protected token, but never
        # metadata that points at a transfer id whose cleanup token disappeared.
        self.metadata_path.unlink(missing_ok=True)
        self.secret_store.clear()
