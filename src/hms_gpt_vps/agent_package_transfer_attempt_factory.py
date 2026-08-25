from __future__ import annotations

import os
from pathlib import Path

from .agent_package_transfer_attempt import AgentPackageTransferAttemptStore
from .windows_dpapi import DpapiSecretStore, protect_bytes, unprotect_bytes


TRANSFER_ATTEMPT_METADATA_FILENAME = "agent-package-transfer-attempt.json"
TRANSFER_ATTEMPT_TOKEN_FILENAME = "agent-package-transfer-token.dpapi"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_TRANSFER_TOKEN_DPAPI_BYTES = 64 * 1024


def _assert_path_chain_not_reparse(path: Path) -> None:
    """Reject symlink/reparse components in the host authority-store path."""
    chain: list[Path] = []
    current = path.expanduser().absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent

    for candidate in reversed(chain):
        if candidate.is_symlink():
            raise ValueError("instance runtime directory path must not traverse a symbolic link")
        try:
            stat_result = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = int(getattr(stat_result, "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("instance runtime directory path must not traverse a reparse point")


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


class TransferTokenDpapiStore(DpapiSecretStore):
    """DPAPI store with pinned file and parent-directory authority.

    Reads and writes pin the lexical token file identity during each operation.
    The parent directory identity is also pinned across the lifetime of this
    store, so a normal-directory rename/substitution between operations cannot
    silently redirect later DPAPI reads or writes.

    ``clear`` remains deliberately non-destructive for the transfer-attempt
    use-case: transfer metadata, not this ciphertext, owns cleanup authority.
    Other users may safely overwrite the same pinned lexical file with a new
    encrypted value.
    """

    def __init__(self, path: Path) -> None:
        super().__init__(path.expanduser().absolute())
        self._parent_identity: os.stat_result | None = None
        _assert_path_chain_not_reparse(self.path.parent)
        if self.path.parent.exists():
            if not self.path.parent.is_dir():
                raise ValueError("transfer token parent must be a directory")
            self._parent_identity = self.path.parent.stat()

    def _assert_parent_authority(self) -> os.stat_result:
        _assert_path_chain_not_reparse(self.path.parent)
        if not self.path.parent.is_dir():
            raise ValueError("transfer token parent must be an existing directory")
        current = self.path.parent.stat()
        if self._parent_identity is None:
            self._parent_identity = current
        elif not _same_file_identity(self._parent_identity, current):
            raise ValueError("transfer token parent authority changed")
        return current

    def _assert_authority(self) -> None:
        _assert_path_chain_not_reparse(self.path)
        self._assert_parent_authority()
        if self.path.exists() and not self.path.is_file():
            raise ValueError("transfer token authority path is not a regular file")

    def save_text(self, secret: str) -> None:
        if not secret:
            raise ValueError("secret must not be empty")
        protected = protect_bytes(secret.encode("utf-8"))
        if not protected or len(protected) > _MAX_TRANSFER_TOKEN_DPAPI_BYTES:
            raise ValueError("protected transfer token size is outside supported bounds")

        self._assert_authority()
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
        created = False
        try:
            fd = os.open(self.path, flags)
        except FileNotFoundError:
            fd = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True

        try:
            opened_stat = os.fstat(fd)
            self._assert_authority()
            current_stat = self.path.stat()
            if not _same_file_identity(opened_stat, current_stat):
                raise ValueError("transfer token authority changed during open")
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            view = memoryview(protected)
            written = 0
            while written < len(view):
                count = os.write(fd, view[written:])
                if count <= 0:
                    raise OSError("transfer token write made no progress")
                written += count
            os.fsync(fd)
            final_stat = os.fstat(fd)
            if final_stat.st_size != len(protected):
                raise ValueError("protected transfer token write size mismatch")
            self._assert_authority()
            current_stat = self.path.stat()
            if not _same_file_identity(opened_stat, current_stat):
                raise ValueError("transfer token authority changed during write")
        finally:
            os.close(fd)
        _ = created

    def load_text(self) -> str:
        self._assert_authority()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        fd = os.open(self.path, flags)
        try:
            opened_stat = os.fstat(fd)
            if (
                opened_stat.st_size <= 0
                or opened_stat.st_size > _MAX_TRANSFER_TOKEN_DPAPI_BYTES
            ):
                raise ValueError("protected transfer token size is outside supported bounds")
            self._assert_authority()
            current_stat = self.path.stat()
            if not _same_file_identity(opened_stat, current_stat):
                raise ValueError("transfer token authority changed during open")
            chunks: list[bytes] = []
            remaining = opened_stat.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 8192))
                if not chunk:
                    raise ValueError("protected transfer token changed during read")
                chunks.append(chunk)
                remaining -= len(chunk)
            protected = b"".join(chunks)
            if len(protected) != opened_stat.st_size:
                raise ValueError("protected transfer token changed during read")
            self._assert_authority()
            current_stat = self.path.stat()
            if not _same_file_identity(opened_stat, current_stat):
                raise ValueError("transfer token authority changed during read")
        finally:
            os.close(fd)
        return unprotect_bytes(protected).decode("utf-8")

    def clear(self) -> None:
        return None


def create_dpapi_agent_package_transfer_attempt_store(
    instance_runtime_dir: Path,
) -> AgentPackageTransferAttemptStore:
    """Create the production current-user-DPAPI transfer-attempt store."""
    runtime_dir = instance_runtime_dir.expanduser().absolute()
    _assert_path_chain_not_reparse(runtime_dir)
    if runtime_dir.exists() and not runtime_dir.is_dir():
        raise ValueError("instance runtime directory is unsafe")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    _assert_path_chain_not_reparse(runtime_dir)
    if not runtime_dir.is_dir():
        raise ValueError("instance runtime directory is unsafe")

    metadata_path = runtime_dir / TRANSFER_ATTEMPT_METADATA_FILENAME
    token_path = runtime_dir / TRANSFER_ATTEMPT_TOKEN_FILENAME
    return AgentPackageTransferAttemptStore(
        metadata_path,
        TransferTokenDpapiStore(token_path),
        secret_path=token_path,
    )
