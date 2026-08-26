from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
from tempfile import NamedTemporaryFile

from .bridge_service_secret_storage import BridgeServiceSecretStorageConfig
from .qualification_file_authority import (
    lexical_absolute,
    path_chain_has_redirect,
    read_file_pinned,
)
from .windows_dpapi import protect_bytes_machine, unprotect_bytes


OPENAI_TUNNEL_CLIENT_VERSION = "v0.0.12"
OPENAI_TUNNEL_CLIENT_ASSET = "tunnel-client-runtime-v0.0.12-windows-amd64.zip"
OPENAI_TUNNEL_CLIENT_ASSET_SIZE = 6_950_001
OPENAI_TUNNEL_CLIENT_SHA256 = (
    "0721098f9edda72cc36f938adcb12cd6a0c49c6c0be7ad6ab6e412f966585f2e"
)
OPENAI_TUNNEL_CLIENT_EXECUTABLE = "tunnel-client-runtime.exe"
HMS_MCP_SERVER_URL = "http://127.0.0.1:8765/mcp"
TUNNEL_READY_PATH = "/readyz"

TUNNEL_API_KEY_MAGIC = b"HMS-TUNNEL-API-SVC-V1\x00"
_MAX_PROTECTED_API_KEY_BYTES = 64 * 1024
_MAX_API_KEY_BYTES = 16 * 1024
_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
_TUNNEL_ID_RE = re.compile(r"^tunnel_[0-9a-f]{32}$")
_ALLOWED_PARENT_ENV = ("SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP")


class SecureMcpTunnelError(RuntimeError):
    pass


class SecureMcpTunnelIntegrityError(SecureMcpTunnelError):
    pass


@dataclass(frozen=True)
class TunnelClientPackagePin:
    version: str = OPENAI_TUNNEL_CLIENT_VERSION
    asset_name: str = OPENAI_TUNNEL_CLIENT_ASSET
    asset_size: int = OPENAI_TUNNEL_CLIENT_ASSET_SIZE
    sha256: str = OPENAI_TUNNEL_CLIENT_SHA256
    executable_name: str = OPENAI_TUNNEL_CLIENT_EXECUTABLE

    def validate(self) -> None:
        if self.version != OPENAI_TUNNEL_CLIENT_VERSION:
            raise SecureMcpTunnelIntegrityError("OpenAI tunnel-client version differs from authority")
        if self.asset_name != OPENAI_TUNNEL_CLIENT_ASSET:
            raise SecureMcpTunnelIntegrityError("OpenAI tunnel-client asset differs from authority")
        if self.asset_size != OPENAI_TUNNEL_CLIENT_ASSET_SIZE:
            raise SecureMcpTunnelIntegrityError("OpenAI tunnel-client asset size differs from authority")
        if self.sha256 != OPENAI_TUNNEL_CLIENT_SHA256:
            raise SecureMcpTunnelIntegrityError("OpenAI tunnel-client SHA-256 differs from authority")
        if self.executable_name != OPENAI_TUNNEL_CLIENT_EXECUTABLE:
            raise SecureMcpTunnelIntegrityError("OpenAI tunnel-client executable differs from authority")

    def verify_archive(self, archive: Path) -> str:
        self.validate()
        if not isinstance(archive, Path):
            raise TypeError("archive must be a pathlib.Path")
        authority = lexical_absolute(archive)
        if authority.name != self.asset_name:
            raise SecureMcpTunnelIntegrityError("OpenAI tunnel-client archive filename differs from authority")
        try:
            raw = read_file_pinned(
                authority,
                max_bytes=_MAX_ARCHIVE_BYTES,
                label="OpenAI tunnel-client archive",
            )
        except Exception as exc:
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel-client archive could not be read from stable file authority"
            ) from exc
        if len(raw) != self.asset_size:
            raise SecureMcpTunnelIntegrityError("OpenAI tunnel-client archive size differs from authority")
        actual = hashlib.sha256(raw).hexdigest()
        if not secrets.compare_digest(actual, self.sha256):
            raise SecureMcpTunnelIntegrityError("OpenAI tunnel-client archive SHA-256 differs from authority")
        return actual


def _validate_tunnel_id(tunnel_id: str) -> str:
    if not isinstance(tunnel_id, str) or not _TUNNEL_ID_RE.fullmatch(tunnel_id):
        raise SecureMcpTunnelError("CONTROL_PLANE_TUNNEL_ID is invalid")
    return tunnel_id


def _validate_api_key(api_key: str) -> bytes:
    if not isinstance(api_key, str):
        raise TypeError("api_key must be a string")
    if not api_key or api_key != api_key.strip():
        raise SecureMcpTunnelError("CONTROL_PLANE_API_KEY is empty or contains edge whitespace")
    if any(char in api_key for char in ("\x00", "\r", "\n")):
        raise SecureMcpTunnelError("CONTROL_PLANE_API_KEY contains a forbidden control character")
    try:
        encoded = api_key.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise SecureMcpTunnelError("CONTROL_PLANE_API_KEY is not valid UTF-8 text") from exc
    if len(encoded) > _MAX_API_KEY_BYTES:
        raise SecureMcpTunnelError("CONTROL_PLANE_API_KEY exceeds safety bound")
    return encoded


def _machine_tunnel_api_key_protect(data: bytes) -> bytes:
    return protect_bytes_machine(
        data,
        description="HMS-GPT-VPS OpenAI tunnel runtime API key service v1",
    )


class TunnelRuntimeApiKeyStore:
    """Create-once LocalMachine-DPAPI custody for the restricted tunnel runtime key."""

    def __init__(
        self,
        config: BridgeServiceSecretStorageConfig,
        *,
        protector=None,
        unprotector=None,
    ) -> None:
        config.validate()
        self.config = config
        self.path = lexical_absolute(config.tunnel_api_key_path)
        self._protect = protector or _machine_tunnel_api_key_protect
        self._unprotect = unprotector or unprotect_bytes

    def _assert_safe(self) -> None:
        if path_chain_has_redirect(self.path):
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API-key path traverses a link or reparse point"
            )
        if not self.path.parent.is_dir():
            raise SecureMcpTunnelError(
                "Bridge service secret root must exist before tunnel API-key access"
            )
        if self.path.exists() and not self.path.is_file():
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API-key authority is not a regular file"
            )

    def exists(self) -> bool:
        self._assert_safe()
        return self.path.is_file()

    def _decode(self, raw: bytes) -> str:
        if len(raw) > _MAX_PROTECTED_API_KEY_BYTES or not raw.startswith(TUNNEL_API_KEY_MAGIC):
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API key has an invalid service-machine envelope"
            )
        protected = raw[len(TUNNEL_API_KEY_MAGIC) :]
        if not protected:
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API-key protected payload is empty"
            )
        try:
            plain = self._unprotect(protected)
        except Exception as exc:
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API key could not be unprotected"
            ) from exc
        if not isinstance(plain, bytes):
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API-key unprotector returned an invalid payload"
            )
        try:
            value = plain.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API-key plaintext is not valid UTF-8"
            ) from exc
        try:
            _validate_api_key(value)
        except (SecureMcpTunnelError, TypeError) as exc:
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API-key plaintext is invalid"
            ) from exc
        return value

    def load(self) -> str:
        self._assert_safe()
        try:
            raw = read_file_pinned(
                self.path,
                max_bytes=_MAX_PROTECTED_API_KEY_BYTES,
                label="OpenAI tunnel runtime API-key authority",
            )
        except Exception as exc:
            raise SecureMcpTunnelIntegrityError(
                "OpenAI tunnel runtime API-key authority could not be read safely"
            ) from exc
        return self._decode(raw)

    def provision(self, api_key: str) -> None:
        plain = _validate_api_key(api_key)
        self._assert_safe()
        if self.path.exists():
            if not secrets.compare_digest(self.load(), api_key):
                raise SecureMcpTunnelIntegrityError(
                    "OpenAI tunnel runtime API key already exists with different authority"
                )
            return
        protected = self._protect(plain)
        if not isinstance(protected, bytes) or not protected:
            raise SecureMcpTunnelError(
                "OpenAI tunnel runtime API-key protector returned empty ciphertext"
            )
        envelope = TUNNEL_API_KEY_MAGIC + protected
        if len(envelope) > _MAX_PROTECTED_API_KEY_BYTES:
            raise SecureMcpTunnelError(
                "OpenAI tunnel runtime API-key ciphertext exceeds safety bound"
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
                if not secrets.compare_digest(self.load(), api_key):
                    raise SecureMcpTunnelIntegrityError(
                        "Concurrent tunnel API-key publication resolved to different authority"
                    )
                return
            self._assert_safe()
            if not secrets.compare_digest(self.load(), api_key):
                raise SecureMcpTunnelIntegrityError(
                    "OpenAI tunnel runtime API-key publication failed readback"
                )
        finally:
            if temp_path is not None and not path_chain_has_redirect(temp_path):
                temp_path.unlink(missing_ok=True)


@dataclass(frozen=True)
class TunnelLaunchSpec:
    executable: Path
    argv: tuple[str, str]
    tunnel_id: str
    mcp_server_url: str = HMS_MCP_SERVER_URL
    readiness_path: str = TUNNEL_READY_PATH


def build_tunnel_launch_spec(executable: Path, tunnel_id: str) -> TunnelLaunchSpec:
    if not isinstance(executable, Path):
        raise TypeError("executable must be a pathlib.Path")
    authority = lexical_absolute(executable)
    if path_chain_has_redirect(authority):
        raise SecureMcpTunnelIntegrityError(
            "OpenAI tunnel-client executable path traverses a link or reparse point"
        )
    if not authority.is_file():
        raise SecureMcpTunnelIntegrityError(
            "OpenAI tunnel-client executable must already exist as a regular file"
        )
    if authority.name.casefold() != OPENAI_TUNNEL_CLIENT_EXECUTABLE.casefold():
        raise SecureMcpTunnelIntegrityError(
            "OpenAI tunnel-client executable basename differs from authority"
        )
    resolved_tunnel_id = _validate_tunnel_id(tunnel_id)
    return TunnelLaunchSpec(
        executable=authority,
        argv=(str(authority), "run"),
        tunnel_id=resolved_tunnel_id,
    )


def build_tunnel_child_environment(
    base_environment: Mapping[str, str],
    *,
    tunnel_id: str,
    api_key: str,
) -> dict[str, str]:
    if not isinstance(base_environment, Mapping):
        raise TypeError("base_environment must be a mapping")
    resolved_tunnel_id = _validate_tunnel_id(tunnel_id)
    _validate_api_key(api_key)
    folded: dict[str, tuple[str, str]] = {}
    for key, value in base_environment.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("base_environment keys and values must be strings")
        if "\x00" in key or "\x00" in value:
            raise SecureMcpTunnelError("base_environment contains a NUL character")
        folded[key.casefold()] = (key, value)
    child: dict[str, str] = {}
    for canonical in _ALLOWED_PARENT_ENV:
        inherited = folded.get(canonical.casefold())
        if inherited is not None:
            child[canonical] = inherited[1]
    child["CONTROL_PLANE_TUNNEL_ID"] = resolved_tunnel_id
    child["CONTROL_PLANE_API_KEY"] = api_key
    child["MCP_SERVER_URL"] = HMS_MCP_SERVER_URL
    return child


def tunnel_readiness_status_is_ready(status_code: int) -> bool:
    return isinstance(status_code, int) and not isinstance(status_code, bool) and status_code == 200
