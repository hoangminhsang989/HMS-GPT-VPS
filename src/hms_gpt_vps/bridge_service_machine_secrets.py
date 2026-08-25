from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from .agent_device_credential_store import (
    _ProtectedAgentDeviceCredentialStore,
)
from .agent_transport_protocol import AgentDeviceCredential
from .bridge_service_secret_storage import (
    BridgeServiceSecretStorageConfig,
    service_agent_credential_path,
)
from .pairing_exchange import PAIRING_EXCHANGE_KEY_BYTES, PairingExchangeKey
from .qualification_file_authority import lexical_absolute, path_chain_has_redirect
from .windows_dpapi import protect_bytes_machine, unprotect_bytes


SERVICE_MACHINE_CREDENTIAL_SCOPE = "local-machine-service"
SERVICE_PAIRING_KEY_MAGIC = b"HMS-PXK-SVC-V1\x00"
_MAX_PROTECTED_KEY_BYTES = 64 * 1024


class BridgeServiceMachineSecretError(RuntimeError):
    pass


class BridgeServiceMachineSecretIntegrityError(BridgeServiceMachineSecretError):
    pass


ProtectFn = Callable[[bytes], bytes]
UnprotectFn = Callable[[bytes], bytes]


def _machine_pairing_protect(data: bytes) -> bytes:
    return protect_bytes_machine(
        data,
        description="HMS-GPT-VPS HMSBridge pairing exchange key service v1",
    )


def _machine_credential_protect(data: bytes) -> bytes:
    return protect_bytes_machine(
        data,
        description="HMS-GPT-VPS HMSBridge Agent credential service v1",
    )


class BridgeServicePairingExchangeKeyStore:
    """Create-once LocalMachine-DPAPI store for the HMSBridge virtual account."""

    def __init__(
        self,
        path: Path,
        *,
        protector: ProtectFn | None = None,
        unprotector: UnprotectFn | None = None,
    ) -> None:
        if not isinstance(path, Path):
            raise TypeError("path must be a pathlib.Path")
        self.path = lexical_absolute(path)
        self._protect = protector or _machine_pairing_protect
        self._unprotect = unprotector or unprotect_bytes

    def _assert_safe(self) -> None:
        if path_chain_has_redirect(self.path):
            raise BridgeServiceMachineSecretIntegrityError(
                "HMSBridge pairing key path traverses a link or reparse point"
            )
        if not self.path.parent.is_dir():
            raise BridgeServiceMachineSecretError(
                "HMSBridge service secret root must exist before pairing-key access"
            )
        if self.path.exists() and not self.path.is_file():
            raise BridgeServiceMachineSecretIntegrityError(
                "HMSBridge pairing-key authority is not a regular file"
            )

    def exists(self) -> bool:
        self._assert_safe()
        return self.path.is_file()

    def _decode(self, raw: bytes) -> PairingExchangeKey:
        if len(raw) > _MAX_PROTECTED_KEY_BYTES or not raw.startswith(SERVICE_PAIRING_KEY_MAGIC):
            raise BridgeServiceMachineSecretIntegrityError(
                "HMSBridge pairing key has an invalid service-machine envelope"
            )
        protected = raw[len(SERVICE_PAIRING_KEY_MAGIC) :]
        if not protected:
            raise BridgeServiceMachineSecretIntegrityError(
                "HMSBridge pairing key protected payload is empty"
            )
        try:
            plain = self._unprotect(protected)
        except Exception as exc:
            raise BridgeServiceMachineSecretIntegrityError(
                "HMSBridge pairing key could not be unprotected"
            ) from exc
        if len(plain) != PAIRING_EXCHANGE_KEY_BYTES:
            raise BridgeServiceMachineSecretIntegrityError(
                "HMSBridge pairing key plaintext length is invalid"
            )
        return PairingExchangeKey(bytes(plain))

    def load(self) -> PairingExchangeKey:
        self._assert_safe()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        fd = os.open(self.path, flags)
        try:
            before = os.fstat(fd)
            if before.st_size <= len(SERVICE_PAIRING_KEY_MAGIC) or before.st_size > _MAX_PROTECTED_KEY_BYTES:
                raise BridgeServiceMachineSecretIntegrityError(
                    "HMSBridge pairing key file size is invalid"
                )
            self._assert_safe()
            current = self.path.stat()
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise BridgeServiceMachineSecretIntegrityError(
                    "HMSBridge pairing key authority changed during open"
                )
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(_MAX_PROTECTED_KEY_BYTES + 1)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or len(raw) != before.st_size:
                raise BridgeServiceMachineSecretIntegrityError(
                    "HMSBridge pairing key changed during read"
                )
            self._assert_safe()
            current = self.path.stat()
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise BridgeServiceMachineSecretIntegrityError(
                    "HMSBridge pairing key authority changed after read"
                )
        finally:
            os.close(fd)
        return self._decode(raw)

    def load_or_create(self) -> PairingExchangeKey:
        self._assert_safe()
        if self.path.exists():
            return self.load()
        key = PairingExchangeKey.generate()
        protected = self._protect(key.export_for_secret_store())
        if not protected:
            raise BridgeServiceMachineSecretError(
                "HMSBridge pairing-key protector returned empty ciphertext"
            )
        envelope = SERVICE_PAIRING_KEY_MAGIC + protected
        if len(envelope) > _MAX_PROTECTED_KEY_BYTES:
            raise BridgeServiceMachineSecretError(
                "HMSBridge pairing-key ciphertext exceeds safety bound"
            )
        temp_path: Path | None = None
        try:
            with NamedTemporaryFile(
                "wb",
                dir=self.path.parent,
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(envelope)
                handle.flush()
                os.fsync(handle.fileno())
                temp_path = Path(handle.name)
            self._assert_safe()
            try:
                os.link(temp_path, self.path)
            except FileExistsError:
                return self.load()
            self._assert_safe()
            return key
        finally:
            if temp_path is not None and not path_chain_has_redirect(temp_path):
                temp_path.unlink(missing_ok=True)


class BridgeServiceAgentDeviceCredentialStore(_ProtectedAgentDeviceCredentialStore):
    """LocalMachine-DPAPI credential store scoped by exact service-directory ACLs."""

    def __init__(
        self,
        path: Path,
        *,
        protector: ProtectFn | None = None,
        unprotector: UnprotectFn | None = None,
    ) -> None:
        super().__init__(
            path,
            protection_scope=SERVICE_MACHINE_CREDENTIAL_SCOPE,
            protector=protector or _machine_credential_protect,
            unprotector=unprotector or unprotect_bytes,
            create_parent=False,
        )


class BridgeServiceAgentCredentialResolver:
    def __init__(self, config: BridgeServiceSecretStorageConfig) -> None:
        config.validate()
        self.config = config

    def _store(self, instance_id: str) -> BridgeServiceAgentDeviceCredentialStore:
        return BridgeServiceAgentDeviceCredentialStore(
            service_agent_credential_path(self.config, instance_id)
        )

    def for_request(self, instance_id: str, device_id: str) -> AgentDeviceCredential:
        return self._store(instance_id).load(
            expected_instance_id=instance_id,
            expected_device_id=device_id,
        )

    def for_command(self, instance_id: str) -> AgentDeviceCredential:
        return self._store(instance_id).load(
            expected_instance_id=instance_id,
        )
