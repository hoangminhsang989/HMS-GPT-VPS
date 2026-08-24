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
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


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


def _path_chain_has_redirect(path: Path) -> bool:
    """Observe symlink/junction/reparse redirects without resolving them away."""

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
    schema_version = payload.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != AGENT_DEVICE_CREDENTIAL_SCHEMA_VERSION
    ):
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
        # Preserve the lexical authority path. resolve() would erase evidence of
        # a symlink/junction/reparse redirect before this store can reject it.
        self.path = path.expanduser().absolute()
        self.protection_scope = protection_scope
        self._protect = protector
        self._unprotect = unprotector
        self._create_parent = create_parent

    def _assert_safe_authority_path(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise AgentDeviceCredentialIntegrityError(
                "Agent device credential authority path traverses a link or reparse point"
            )
        parent = self.path.parent
        if parent.exists() and not parent.is_dir():
            raise AgentDeviceCredentialIntegrityError(
                "Agent device credential parent authority is not a directory"
            )
        if self.path.exists() and not self.path.is_file():
            raise AgentDeviceCredentialIntegrityError(
                "Agent device credential authority path is not a regular file"
            )

    def exists(self) -> bool:
        self._assert_safe_authority_path()
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
        self._assert_safe_authority_path()
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
        raw = self.path.read_bytes()
        self._assert_safe_authority_path()
        if len(raw) != stat.st_size:
            raise AgentDeviceCredentialIntegrityError(
                "protected Agent device credential changed during read"
            )
        credential = self._decode_file(
            raw,
            expected_instance_id=expected_instance_id,
            expected_device_id=expected_device_id,
        )
        self._assert_safe_authority_path()
        return credential

    def save_create_only(self, credential: AgentDeviceCredential) -> AgentDeviceCredential:
        """Persist one stable credential or prove an identical one already exists.

        Existing credentials are never silently replaced. This is important on
        both sides: the Bridge must not silently rebind a managed instance, and
        the guest Agent must not rotate its transport identity merely because a
        provisioning step is retried. The lexical authority path is revalidated
        around every filesystem mutation so a later redirect cannot retarget the
        DPAPI credential store.
        """
        credential.validate()
        self._assert_safe_authority_path()
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
            self._assert_safe_authority_path()
        elif not self.path.parent.is_dir():
            raise AgentDeviceCredentialStoreError(
                "guest Agent state directory must exist with managed ACL before credential write"
            )
        else:
            self._assert_safe_authority_path()

        plain = _serialize_credential(
            credential,
            protection_scope=self.protection_scope,
        )
        protected = self._protect(plain)
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
            self._assert_safe_authority_path()
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
            self._assert_safe_authority_path()
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
            self._assert_safe_authority_path()
            return credential
        finally:
            if temp_path is not None and not _path_chain_has_redirect(temp_path):
                # If the parent authority was redirected concurrently, leave an
                # inert orphan temp in the original location rather than risk a
                # destructive unlink through attacker-controlled redirection.
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
