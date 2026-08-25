from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable
from urllib.parse import urlsplit

from .bridge_oauth_introspection_secret_storage import (
    DEFAULT_BRIDGE_OAUTH_INTROSPECTION_SECRET_PATH,
    prove_bridge_oauth_introspection_secret_storage,
    provision_bridge_oauth_introspection_secret_storage,
)
from .bridge_service_config_storage import (
    prove_bridge_service_runtime_config_storage,
    provision_bridge_service_runtime_config_storage,
)
from .qualification_file_authority import lexical_absolute, path_chain_has_redirect
from .windows_dpapi import protect_bytes_machine, unprotect_bytes


OAUTH_INTROSPECTION_CREDENTIAL_SCHEMA_VERSION = 1
OAUTH_INTROSPECTION_SECRET_MAGIC = b"HMS-OAUTH-INTROSPECT-SVC-V1\x00"
_MAX_PROTECTED_SECRET_BYTES = 128 * 1024
_MAX_PLAINTEXT_SECRET_BYTES = 16 * 1024
ProtectFn = Callable[[bytes], bytes]
UnprotectFn = Callable[[bytes], bytes]


class BridgeOAuthIntrospectionCredentialError(RuntimeError):
    pass


class BridgeOAuthIntrospectionCredentialIntegrityError(BridgeOAuthIntrospectionCredentialError):
    pass


def _require_https_issuer(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 2048:
        raise BridgeOAuthIntrospectionCredentialError("issuer_url is invalid")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise BridgeOAuthIntrospectionCredentialError("issuer_url must be a canonical HTTPS issuer URL")
    return value


def _require_client_id(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 512:
        raise BridgeOAuthIntrospectionCredentialError("client_id is invalid")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise BridgeOAuthIntrospectionCredentialError("client_id contains control characters")
    return value


def _require_client_secret(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 8192:
        raise BridgeOAuthIntrospectionCredentialError("client_secret is invalid")
    if any(c in value for c in ("\x00", "\r", "\n")):
        raise BridgeOAuthIntrospectionCredentialError("client_secret contains unsupported control characters")
    return value


@dataclass(frozen=True)
class BridgeOAuthIntrospectionCredential:
    issuer_url: str
    client_id: str
    client_secret: str = field(repr=False)
    schema_version: int = OAUTH_INTROSPECTION_CREDENTIAL_SCHEMA_VERSION

    def validate(self) -> None:
        if self.schema_version != OAUTH_INTROSPECTION_CREDENTIAL_SCHEMA_VERSION:
            raise BridgeOAuthIntrospectionCredentialError("unsupported OAuth introspection credential schema_version")
        _require_https_issuer(self.issuer_url)
        _require_client_id(self.client_id)
        _require_client_secret(self.client_secret)

    def to_bytes(self) -> bytes:
        self.validate()
        data = json.dumps(
            {"schema_version": self.schema_version, "issuer_url": self.issuer_url, "client_id": self.client_id, "client_secret": self.client_secret},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        if len(data) > _MAX_PLAINTEXT_SECRET_BYTES:
            raise BridgeOAuthIntrospectionCredentialError("OAuth introspection credential plaintext exceeds safety bound")
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> "BridgeOAuthIntrospectionCredential":
        if not isinstance(data, bytes) or not data or len(data) > _MAX_PLAINTEXT_SECRET_BYTES:
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential plaintext size is invalid")

        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for key, value in items:
                if key in out:
                    raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential contains duplicate fields")
                out[key] = value
            return out

        try:
            raw = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential plaintext is invalid") from exc
        expected = {"schema_version", "issuer_url", "client_id", "client_secret"}
        if not isinstance(raw, dict) or set(raw) != expected:
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential fields differ from authority")
        version = raw["schema_version"]
        if not isinstance(version, int) or isinstance(version, bool):
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential schema_version is invalid")
        credential = cls(
            schema_version=version,
            issuer_url=_require_https_issuer(raw["issuer_url"]),
            client_id=_require_client_id(raw["client_id"]),
            client_secret=_require_client_secret(raw["client_secret"]),
        )
        credential.validate()
        return credential


def _protect(data: bytes) -> bytes:
    return protect_bytes_machine(data, description="HMS-GPT-VPS HMSBridge OAuth introspection client credential v1")


class BridgeOAuthIntrospectionCredentialStore:
    def __init__(self, path: Path = DEFAULT_BRIDGE_OAUTH_INTROSPECTION_SECRET_PATH, *, protector: ProtectFn | None = None, unprotector: UnprotectFn | None = None) -> None:
        if not isinstance(path, Path):
            raise TypeError("path must be pathlib.Path")
        self.path = lexical_absolute(path)
        self._protect = protector or _protect
        self._unprotect = unprotector or unprotect_bytes

    def _assert_safe(self) -> None:
        if path_chain_has_redirect(self.path):
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential path traverses a link or reparse point")
        if not self.path.parent.is_dir():
            raise BridgeOAuthIntrospectionCredentialError("OAuth introspection credential parent must already exist")
        if self.path.exists() and not self.path.is_file():
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential authority is not a regular file")

    def save_create_only(self, credential: BridgeOAuthIntrospectionCredential) -> None:
        if not isinstance(credential, BridgeOAuthIntrospectionCredential):
            raise TypeError("credential must be a BridgeOAuthIntrospectionCredential")
        credential.validate()
        self._assert_safe()
        if self.path.exists():
            raise FileExistsError(self.path)
        protected = self._protect(credential.to_bytes())
        envelope = OAUTH_INTROSPECTION_SECRET_MAGIC + protected
        if not protected or len(envelope) > _MAX_PROTECTED_SECRET_BYTES:
            raise BridgeOAuthIntrospectionCredentialError("OAuth introspection credential ciphertext is invalid")
        temp: Path | None = None
        try:
            with NamedTemporaryFile("wb", dir=self.path.parent, prefix=self.path.name + ".", suffix=".tmp", delete=False) as handle:
                handle.write(envelope)
                handle.flush()
                os.fsync(handle.fileno())
                temp = Path(handle.name)
            self._assert_safe()
            os.link(temp, self.path)
            self._assert_safe()
        finally:
            if temp is not None and not path_chain_has_redirect(temp):
                temp.unlink(missing_ok=True)

    def load(self, *, expected_issuer_url: str) -> BridgeOAuthIntrospectionCredential:
        issuer = _require_https_issuer(expected_issuer_url)
        self._assert_safe()
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            before = os.fstat(fd)
            if before.st_size <= len(OAUTH_INTROSPECTION_SECRET_MAGIC) or before.st_size > _MAX_PROTECTED_SECRET_BYTES:
                raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential protected size is invalid")
            self._assert_safe()
            current = self.path.stat()
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential authority changed during open")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(_MAX_PROTECTED_SECRET_BYTES + 1)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or len(raw) != before.st_size:
                raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential changed during read")
            self._assert_safe()
            current = self.path.stat()
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential authority changed after read")
        finally:
            os.close(fd)
        if not raw.startswith(OAUTH_INTROSPECTION_SECRET_MAGIC):
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential envelope magic is invalid")
        try:
            plaintext = self._unprotect(raw[len(OAUTH_INTROSPECTION_SECRET_MAGIC):])
        except Exception as exc:
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential could not be unprotected") from exc
        credential = BridgeOAuthIntrospectionCredential.from_bytes(plaintext)
        if credential.issuer_url != issuer:
            raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection credential issuer differs from runtime authority")
        return credential


def provision_bridge_oauth_introspection_credential(credential: BridgeOAuthIntrospectionCredential) -> None:
    credential.validate()
    provision_bridge_service_runtime_config_storage()
    BridgeOAuthIntrospectionCredentialStore().save_create_only(credential)
    provision_bridge_oauth_introspection_secret_storage()


def load_protected_bridge_oauth_introspection_credential(expected_issuer_url: str) -> BridgeOAuthIntrospectionCredential:
    issuer = _require_https_issuer(expected_issuer_url)
    config_before = prove_bridge_service_runtime_config_storage()
    secret_before = prove_bridge_oauth_introspection_secret_storage()
    credential = BridgeOAuthIntrospectionCredentialStore().load(expected_issuer_url=issuer)
    secret_after = prove_bridge_oauth_introspection_secret_storage()
    config_after = prove_bridge_service_runtime_config_storage()
    if secret_before["secret_sha256"] != secret_after["secret_sha256"]:
        raise BridgeOAuthIntrospectionCredentialIntegrityError("OAuth introspection secret changed across protected load boundary")
    if config_before["config_sha256"] != config_after["config_sha256"]:
        raise BridgeOAuthIntrospectionCredentialIntegrityError("Bridge runtime config changed across OAuth credential load boundary")
    return credential
