from __future__ import annotations

import base64
from collections.abc import Callable
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .agent_transport_protocol import (
    AGENT_DEVICE_SECRET_BYTES,
    AgentDeviceCredential,
)
from .windows_dpapi import protect_bytes, protect_bytes_machine, unprotect_bytes


AGENT_DEVICE_CREDENTIAL_SCHEMA_VERSION = 1
AGENT_DEVICE_CREDENTIAL_FILE_MAGIC = b"HMS-ADC-V1\x00"
MAX_PROTECTED_DEVICE_CREDENTIAL_BYTES = 64 * 1024
GUEST_DEVICE_CREDENTIAL_FILENAME = "agent-device-credential.dpapi"
BRIDGE_PROTECTION_SCOPE = "current-user"
GUEST_PROTECTION_SCOPE = "local-machine"


class AgentDeviceCredentialStoreError(RuntimeError):
    pass


class AgentDeviceCredentialIntegrityError(AgentDeviceCredentialStoreError):
    pass


class AgentDeviceCredentialConflictError(AgentDeviceCredentialStoreError):
    pass


ProtectFn = Callable[[bytes], bytes]
UnprotectFn = Callable[[bytes], bytes]


def _bridge_protect(data: bytes) -> bytes:
    return protect_bytes(
        data,
        description="HMS-GPT-VPS Bridge Agent device credential v1",
    )


def _guest_protect(data: bytes) -> bytes:
    return protect_bytes_machine(
        data,
        description="HMS-GPT-VPS guest Agent device credential v1",
    )


def _unprotect(data: bytes) -> bytes:
    return unprotect_bytes(data)


def guest_device_credential_path(state_path: Path) -> Path:
    return state_path.expanduser().absolute() / GUEST_DEVICE_CREDENTIAL_FILENAME


def _serialize_credential(
    credential: AgentDeviceCredential,
    *,
    protection_scope: str,
) -> bytes:
    credential.validate()
    payload = {
        "schema_version": AGENT_DEVICE_CREDENTIAL_SCHEMA_VERSION,
        "protection_scope": protection_scope,
        "instance_id": credential.instance_id,
        "device_id": credential.device_id,
        "secret_b64": base64.b64encode(credential.secret).decode("ascii"),
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _deserialize_credential(
    plain: bytes,
    *,
    expected_scope: str,
    expected_instance_id: str | None,
    expected_device_id: str | None,
) -> AgentDeviceCredential:
    try:
        payload = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential plaintext is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential payload must be an object"
        )
    expected_keys = {
        "schema_version",
        "protection_scope",
        "instance_id",
        "device_id",
        "secret_b64",
    }
    if set(payload) != expected_keys:
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential payload fields do not match schema"
        )
    if payload.get("schema_version") != AGENT_DEVICE_CREDENTIAL_SCHEMA_VERSION:
        raise AgentDeviceCredentialIntegrityError(
            "unsupported Agent device credential schema"
        )
    if payload.get("protection_scope") != expected_scope:
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential protection scope mismatch"
        )
    instance_id = payload.get("instance_id")
    device_id = payload.get("device_id")
    secret_b64 = payload.get("secret_b64")
    if not isinstance(instance_id, str) or not isinstance(device_id, str):
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential identity fields are invalid"
        )
    if not isinstance(secret_b64, str):
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential secret encoding is invalid"
        )
    try:
        secret = base64.b64decode(secret_b64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential secret encoding is invalid"
        ) from exc
    if len(secret) != AGENT_DEVICE_SECRET_BYTES:
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential secret has an invalid length"
        )
    try:
        credential = AgentDeviceCredential(
            instance_id=instance_id,
            device_id=device_id,
            secret=bytes(secret),
        )
        credential.validate()
    except (TypeError, ValueError) as exc:
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential identity failed validation"
        ) from exc
    if expected_instance_id is not None and credential.instance_id != expected_instance_id:
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential instance_id mismatch"
        )
    if expected_device_id is not None and credential.device_id != expected_device_id:
        raise AgentDeviceCredentialIntegrityError(
            "Agent device credential device_id mismatch"
        )
    return credential


class _ProtectedAgentDeviceCredentialStore:
    def __init__(
        self,
        path: Path,
        *,
        protection_scope: str,
        protector: ProtectFn,
        unprotector: UnprotectFn,
        create_parent: bool,
    ) -> None:
        self.path = path.expanduser().absolute()
        self.protection_scope = protection_scope
        self._protect = protector
        self._unprotect = unprotector
        self._create_parent = create_parent

    def exists(self) -> bool:
        return self.path.is_file()

    def _decode_file(
        self,
        raw: bytes,
        *,
        expected_instance_id: str | None,
        expected_device_id: str | None,
    ) -> AgentDeviceCredential:
        if len(raw) > MAX_PROTECTED_DEVICE_CREDENTIAL_BYTES:
            raise AgentDeviceCredentialIntegrityError(
                "protected Agent device credential exceeds maximum size"
            )
        if not raw.startswith(AGENT_DEVICE_CREDENTIAL_FILE_MAGIC):
            raise AgentDeviceCredentialIntegrityError(
                "protected Agent device credential has an invalid format marker"
            )
        protected = raw[len(AGENT_DEVICE_CREDENTIAL_FILE_MAGIC) :]
        if not protected:
            raise AgentDeviceCredentialIntegrityError(
                "protected Agent device credential payload is empty"
            )
        try:
            plain = self._unprotect(protected)
        except Exception as exc:
            raise AgentDeviceCredentialIntegrityError(
                "Agent device credential could not be unprotected"
            ) from exc
        return _deserialize_credential(
            plain,
            expected_scope=self.protection_scope,
            expected_instance_id=expected_instance_id,
            expected_device_id=expected_device_id,
        )

    def load(
        self,
        *,
        expected_instance_id: str | None = None,
        expected_device_id: str | None = None,
    ) -> AgentDeviceCredential:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            raise
        if stat.st_size <= len(AGENT_DEVICE_CREDENTIAL_FILE_MAGIC):
            raise AgentDeviceCredentialIntegrityError(
                "protected Agent device credential file is incomplete"
            )
        if stat.st_size > MAX_PROTECTED_DEVICE_CREDENTIAL_BYTES:
            raise AgentDeviceCredentialIntegrityError(
                "protected Agent device credential exceeds maximum size"
            )
        return self._decode_file(
            self.path.read_bytes(),
            expected_instance_id=expected_instance_id,
            expected_device_id=expected_device_id,
        )

    def save_create_only(self, credential: AgentDeviceCredential) -> AgentDeviceCredential:
        """Persist one stable credential or prove an identical one already exists.

        Existing credentials are never silently replaced.  This is important on
        both sides: the Bridge must not silently rebind a managed instance, and
        the guest Agent must not rotate its transport identity merely because a
        provisioning step is retried.
        """
        credential.validate()
        if self.path.exists():
            existing = self.load(
                expected_instance_id=credential.instance_id,
                expected_device_id=credential.device_id,
            )
            if existing != credential:
                raise AgentDeviceCredentialConflictError(
                    "existing Agent device credential conflicts with requested credential"
                )
            return existing

        if self._create_parent:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif not self.path.parent.is_dir():
            raise AgentDeviceCredentialStoreError(
                "guest Agent state directory must exist with managed ACL before credential write"
            )

        plain = _serialize_credential(
            credential,
            protection_scope=self.protection_scope,
        )
        try:
            protected = self._protect(plain)
        except Exception:
            raise
        if not protected:
            raise AgentDeviceCredentialStoreError(
                "protector returned an empty Agent device credential payload"
            )
        envelope = AGENT_DEVICE_CREDENTIAL_FILE_MAGIC + protected
        if len(envelope) > MAX_PROTECTED_DEVICE_CREDENTIAL_BYTES:
            raise AgentDeviceCredentialStoreError(
                "protected Agent device credential exceeds maximum size"
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
            try:
                os.link(temp_path, self.path)
            except FileExistsError:
                existing = self.load(
                    expected_instance_id=credential.instance_id,
                    expected_device_id=credential.device_id,
                )
                if existing != credential:
                    raise AgentDeviceCredentialConflictError(
                        "concurrent Agent device credential publication conflicted"
                    )
                return existing
            return credential
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)


class BridgeAgentDeviceCredentialStore(_ProtectedAgentDeviceCredentialStore):
    """Current-user DPAPI store for the trusted Bridge copy of a device secret."""

    def __init__(
        self,
        path: Path,
        *,
        protector: ProtectFn | None = None,
        unprotector: UnprotectFn | None = None,
    ) -> None:
        super().__init__(
            path,
            protection_scope=BRIDGE_PROTECTION_SCOPE,
            protector=protector or _bridge_protect,
            unprotector=unprotector or _unprotect,
            create_parent=True,
        )


class GuestAgentDeviceCredentialStore(_ProtectedAgentDeviceCredentialStore):
    """Machine-scope DPAPI store inside the guest Agent State directory.

    The parent directory must already exist under the service installer ACL:
    SYSTEM/Admin full control and `NT SERVICE\\HMSAgent` Modify. Machine-scope
    DPAPI permits the bootstrap identity to create a blob that the LocalService
    Agent can later decrypt on the same guest; the State-directory ACL remains
    mandatory because machine scope itself is not a per-service authorization
    boundary.
    """

    def __init__(
        self,
        path: Path,
        *,
        protector: ProtectFn | None = None,
        unprotector: UnprotectFn | None = None,
    ) -> None:
        super().__init__(
            path,
            protection_scope=GUEST_PROTECTION_SCOPE,
            protector=protector or _guest_protect,
            unprotector=unprotector or _unprotect,
            create_parent=False,
        )
