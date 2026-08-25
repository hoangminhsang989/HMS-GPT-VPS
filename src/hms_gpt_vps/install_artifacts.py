from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Protocol

from .answer_media import (
    AnswerMediaArtifact,
    _lexical_absolute,
    _path_chain_has_redirect,
    _same_file_identity,
    _sha256_open_file,
    _target_matches_identity,
    build_answer_media_iso,
)
from .bootstrap_credentials import BootstrapCredential, generate_bootstrap_credential
from .unattend import (
    BootstrapAccount,
    InstallUnattendConfig,
    UnattendConfig,
    generate_install_unattend,
)
from .windows_dpapi import DpapiSecretStore


_MANAGED_ANSWER_ISO_NAME = "hms-answer.iso"


class TextSecretStore(Protocol):
    def save_text(self, secret: str) -> None: ...

    def load_text(self) -> str: ...

    def clear(self) -> None: ...


@dataclass(frozen=True)
class InstallArtifacts:
    answer_iso: Path
    answer_iso_sha256: str
    answer_iso_size: int
    bootstrap_username: str


def _serialize_credential(credential: BootstrapCredential) -> str:
    return json.dumps(
        {"username": credential.username, "password": credential.password},
        separators=(",", ":"),
    )


def _deserialize_credential(payload: str) -> BootstrapCredential:
    raw = json.loads(payload)
    if not isinstance(raw, dict):
        raise ValueError("bootstrap credential payload must be an object")
    username = raw.get("username")
    password = raw.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("bootstrap credential payload is invalid")
    return BootstrapCredential(username=username, password=password)


def _validate_expected_sha256(expected_sha256: str) -> str:
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise ValueError("expected answer ISO SHA-256 must contain 64 hex characters")
    try:
        int(expected_sha256, 16)
    except ValueError as exc:
        raise ValueError("expected answer ISO SHA-256 must be hexadecimal") from exc
    return expected_sha256.lower()


def _require_runtime_authority(runtime_dir: Path, *, create: bool) -> Path:
    runtime = _lexical_absolute(runtime_dir)
    if _path_chain_has_redirect(runtime):
        raise PermissionError(
            "managed runtime directory must not traverse a link or reparse point"
        )
    if create:
        runtime.mkdir(parents=True, exist_ok=True)
    if not runtime.is_dir():
        raise FileNotFoundError("managed runtime directory does not exist")
    if _path_chain_has_redirect(runtime):
        raise PermissionError(
            "managed runtime directory authority changed during validation"
        )
    return runtime


def _require_cleanup_authority(runtime_dir: Path, answer_iso: Path) -> tuple[Path, Path]:
    runtime = _require_runtime_authority(runtime_dir, create=False)
    answer = _lexical_absolute(answer_iso)
    if _path_chain_has_redirect(answer):
        raise PermissionError(
            "managed answer ISO path must not traverse a link or reparse point"
        )
    expected_answer = runtime / _MANAGED_ANSWER_ISO_NAME
    if answer != expected_answer:
        raise ValueError("answer ISO is not the exact managed runtime artifact")
    return runtime, answer


def _verify_opened_answer_iso(fd: int, answer: Path, expected_sha256: str) -> os.stat_result:
    opened_stat = os.fstat(fd)
    if not stat.S_ISREG(opened_stat.st_mode):
        raise ValueError("managed answer ISO path is not a regular file")
    if not _target_matches_identity(answer, opened_stat):
        raise RuntimeError("managed answer ISO authority changed before cleanup read")
    with os.fdopen(fd, "rb", closefd=False) as handle:
        actual_sha256 = _sha256_open_file(handle)
        after_hash = os.fstat(handle.fileno())
    if not _same_file_identity(opened_stat, after_hash):
        raise RuntimeError("managed answer ISO opened-file identity changed during cleanup")
    if actual_sha256.lower() != expected_sha256:
        raise ValueError("managed answer ISO SHA-256 changed before cleanup")
    if not _target_matches_identity(answer, opened_stat):
        raise RuntimeError("managed answer ISO authority changed during cleanup verification")
    return opened_stat


def _delete_verified_answer_iso_posix(answer: Path, expected_sha256: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(answer, flags)
    try:
        opened_stat = _verify_opened_answer_iso(fd, answer, expected_sha256)
        if not _target_matches_identity(answer, opened_stat):
            raise RuntimeError("managed answer ISO authority changed before cleanup delete")
        os.unlink(answer)
        if answer.exists():
            raise RuntimeError("managed answer ISO still exists after cleanup delete")
    finally:
        os.close(fd)


def _delete_verified_answer_iso_windows(answer: Path, expected_sha256: str) -> None:
    import ctypes
    from ctypes import wintypes
    import msvcrt

    generic_read = 0x80000000
    delete_access = 0x00010000
    file_share_read = 0x00000001
    open_existing = 3
    file_attribute_normal = 0x00000080
    file_flag_open_reparse_point = 0x00200000
    file_disposition_info = 4

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    set_file_information = kernel32.SetFileInformationByHandle
    set_file_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    set_file_information.restype = wintypes.BOOL

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", ctypes.c_ubyte)]

    raw_handle = create_file(
        str(answer),
        generic_read | delete_access,
        file_share_read,
        None,
        open_existing,
        file_attribute_normal | file_flag_open_reparse_point,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if raw_handle == invalid_handle:
        error = ctypes.get_last_error()
        raise OSError(error, "unable to open managed answer ISO for exact cleanup")

    fd: int | None = None
    try:
        try:
            fd = msvcrt.open_osfhandle(
                int(raw_handle),
                os.O_RDONLY | getattr(os, "O_BINARY", 0),
            )
        except Exception:
            close_handle(raw_handle)
            raise

        opened_stat = _verify_opened_answer_iso(fd, answer, expected_sha256)
        if not _target_matches_identity(answer, opened_stat):
            raise RuntimeError("managed answer ISO authority changed before exact deletion")

        disposition = FileDispositionInfo(1)
        os_handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
        if not set_file_information(
            os_handle,
            file_disposition_info,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "unable to mark exact managed answer ISO for deletion")
    finally:
        if fd is not None:
            os.close(fd)

    if answer.exists():
        raise RuntimeError("managed answer ISO still exists after exact handle deletion")


def _delete_verified_answer_iso(answer: Path, expected_sha256: str) -> None:
    if os.name == "nt":
        _delete_verified_answer_iso_windows(answer, expected_sha256)
    else:
        # Non-Windows support exists for Linux CI and development only. The
        # production Windows path deletes the already-verified opened handle.
        _delete_verified_answer_iso_posix(answer, expected_sha256)


def prepare_install_artifacts(
    runtime_dir: Path,
    base: UnattendConfig,
    *,
    image_index: int = 1,
    credential: BootstrapCredential | None = None,
    secret_store: TextSecretStore | None = None,
) -> InstallArtifacts:
    """Create the transient answer media and encrypted resume credential.

    Production callers use current-user Windows DPAPI by default. Tests may
    inject an in-memory store. Returned metadata never contains the password.
    """
    runtime_dir = _require_runtime_authority(runtime_dir, create=True)
    credential = credential or generate_bootstrap_credential()
    store = secret_store or DpapiSecretStore(runtime_dir / "bootstrap.dpapi")

    install_config = InstallUnattendConfig(
        base=base,
        bootstrap=BootstrapAccount(
            username=credential.username,
            password=credential.password,
        ),
        image_index=image_index,
        dedicated_blank_disk_acknowledged=True,
    )
    xml = generate_install_unattend(install_config)

    store.save_text(_serialize_credential(credential))
    answer_path = runtime_dir / _MANAGED_ANSWER_ISO_NAME
    try:
        artifact: AnswerMediaArtifact = build_answer_media_iso(answer_path, xml)
    except Exception:
        store.clear()
        raise

    return InstallArtifacts(
        answer_iso=artifact.path,
        answer_iso_sha256=artifact.sha256,
        answer_iso_size=artifact.size,
        bootstrap_username=credential.username,
    )


def load_bootstrap_credential(store: TextSecretStore) -> BootstrapCredential:
    return _deserialize_credential(store.load_text())


def clear_install_secrets(
    answer_iso: Path,
    store: TextSecretStore,
    *,
    expected_sha256: str,
    runtime_dir: Path,
) -> None:
    """Remove the exact managed answer ISO before clearing its transient secret.

    Cleanup is crash-resumable: a missing answer ISO is treated as already
    removed. When the file exists, the production Windows path opens it with
    READ+DELETE access while denying write/delete sharing, hashes that exact
    opened file, revalidates pathname identity, and marks that handle for
    deletion. The DPAPI record is cleared only after the managed pathname is
    absent.
    """
    expected = _validate_expected_sha256(expected_sha256)
    runtime, answer = _require_cleanup_authority(runtime_dir, answer_iso)

    if answer.exists():
        _delete_verified_answer_iso(answer, expected)

    if _path_chain_has_redirect(runtime) or _path_chain_has_redirect(answer):
        raise RuntimeError("managed cleanup authority changed before secret retirement")
    if answer.exists():
        raise RuntimeError("managed answer ISO still exists before secret retirement")

    store.clear()
