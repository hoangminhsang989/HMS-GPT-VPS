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


@dataclass(frozen=True)
class AgentPackageTransferAttempt:
    instance_id: str
    vm_name: str
    manifest_sha256: str
    transfer_id: str
    phase: AgentPackageTransferPhase
    ownership_token: str = field(repr=False, compare=False)

    def validate(self) -> None:
        if not self.instance_id.strip():
            raise ValueError("instance_id is required")
        if not self.vm_name.strip():
            raise ValueError("vm_name is required")
        _require_hex(self.manifest_sha256, 64, "manifest_sha256")
        _require_hex(self.transfer_id, _TRANSFER_ID_HEX_LENGTH, "transfer_id")
        _require_hex(
            self.ownership_token,
            _OWNERSHIP_TOKEN_HEX_LENGTH,
            "ownership_token",
        )
        if not isinstance(self.phase, AgentPackageTransferPhase):
            raise ValueError("phase is invalid")

    def metadata(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": AGENT_PACKAGE_TRANSFER_ATTEMPT_SCHEMA_VERSION,
            "instance_id": self.instance_id,
            "vm_name": self.vm_name,
            "manifest_sha256": self.manifest_sha256,
            "transfer_id": self.transfer_id,
            "phase": self.phase.value,
        }


class AgentPackageTransferAttemptStore:
    """Crash-safe transfer metadata with the destructive token kept in DPAPI storage.

    The JSON record is deliberately non-secret. The ownership token that permits
    deletion of an interrupted guest staging root is stored only through the
    injected protected secret store. A missing/mismatching half of the pair fails
    closed instead of generating a fresh token for an existing transfer id.
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
        }
        if set(raw) != required:
            raise ValueError("Agent package transfer attempt metadata fields are invalid")
        if raw["schema_version"] != AGENT_PACKAGE_TRANSFER_ATTEMPT_SCHEMA_VERSION:
            raise ValueError("unsupported Agent package transfer attempt schema")
        try:
            token = self.secret_store.load_text()
        except FileNotFoundError as exc:
            raise ValueError("Agent package transfer ownership token is missing") from exc
        try:
            phase = AgentPackageTransferPhase(str(raw["phase"]))
        except ValueError as exc:
            raise ValueError("Agent package transfer attempt phase is invalid") from exc
        attempt = AgentPackageTransferAttempt(
            instance_id=str(raw["instance_id"]),
            vm_name=str(raw["vm_name"]),
            manifest_sha256=str(raw["manifest_sha256"]),
            transfer_id=str(raw["transfer_id"]),
            phase=phase,
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
            ownership_token=token,
        )
        attempt.validate()
        # Secret first: a crash here leaves only an orphan secret, which cannot
        # authorize any guest cleanup because no transfer id has been persisted.
        self.secret_store.save_text(token)
        try:
            self._write_metadata(attempt)
        except Exception:
            self.secret_store.clear()
            raise
        return attempt

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
        updated = AgentPackageTransferAttempt(
            instance_id=current.instance_id,
            vm_name=current.vm_name,
            manifest_sha256=current.manifest_sha256,
            transfer_id=current.transfer_id,
            phase=target,
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
