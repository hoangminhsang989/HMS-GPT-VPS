from __future__ import annotations

from contextlib import contextmanager
import hashlib
import math
import os
from pathlib import Path
import time
from typing import Iterator


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_DEFAULT_TIMEOUT_SECONDS = 15.0
_RETRY_SECONDS = 0.05
_WAIT_OBJECT_0 = 0x00000000
_WAIT_ABANDONED = 0x00000080
_WAIT_TIMEOUT = 0x00000102
_WAIT_FAILED = 0xFFFFFFFF


class AuthorityLockError(RuntimeError):
    pass


def _path_chain_has_redirect(path: Path) -> bool:
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


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _assert_lock_authority(path: Path) -> None:
    if _path_chain_has_redirect(path):
        raise AuthorityLockError("authority lock path traverses a link or reparse point")
    if not path.parent.is_dir():
        raise AuthorityLockError("authority lock parent must be an existing directory")
    if path.exists() and not path.is_file():
        raise AuthorityLockError("authority lock path is not a regular file")


def _windows_mutex_name(path: Path) -> str:
    """Derive one case-insensitive Windows-local mutex namespace from lexical authority."""

    lexical = str(path.expanduser().absolute()).casefold().encode("utf-8")
    digest = hashlib.sha256(lexical).hexdigest()
    return f"Local\\HMS-GPT-VPS-Authority-{digest}"


def _acquire_windows_mutex(path: Path, timeout_seconds: float):  # type: ignore[no-untyped-def]
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel32.ReleaseMutex.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateMutexW(None, False, _windows_mutex_name(path))
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateMutexW failed")
    timeout_ms = max(1, int(math.ceil(timeout_seconds * 1000.0)))
    wait_result = int(kernel32.WaitForSingleObject(handle, timeout_ms))
    if wait_result in {_WAIT_OBJECT_0, _WAIT_ABANDONED}:
        return kernel32, handle
    kernel32.CloseHandle(handle)
    if wait_result == _WAIT_TIMEOUT:
        raise AuthorityLockError("timed out waiting for authority lock")
    if wait_result == _WAIT_FAILED:
        raise OSError(ctypes.get_last_error(), "WaitForSingleObject failed")
    raise AuthorityLockError(f"unexpected Windows authority mutex wait result: {wait_result}")


def _release_windows_mutex(kernel32, handle) -> None:  # type: ignore[no-untyped-def]
    import ctypes

    release_error: OSError | None = None
    if not kernel32.ReleaseMutex(handle):
        release_error = OSError(ctypes.get_last_error(), "ReleaseMutex failed")
    if not kernel32.CloseHandle(handle) and release_error is None:
        release_error = OSError(ctypes.get_last_error(), "CloseHandle failed")
    if release_error is not None:
        raise release_error


def _try_posix_lock(fd: int) -> bool:
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock_posix(fd: int) -> None:
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def exclusive_authority_lock(
    path: Path,
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> Iterator[None]:
    """Serialize one authority mutation without stale ownership after crash.

    On Windows, the actual exclusion domain is a named kernel mutex derived from
    the case-insensitive lexical authority path. Renaming/replacing the rendezvous
    file therefore cannot split two production processes into different lock
    domains while one is inside the critical section. A crashed mutex owner is
    reported as WAIT_ABANDONED and ownership transfers to the waiter.

    On non-Windows test/development hosts, an advisory flock on the persistent
    rendezvous inode provides process serialization. In both modes the file is
    never deleted and its lexical identity is checked for tampering before and
    after the critical section.
    """

    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
        raise TypeError("authority lock timeout must be numeric")
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 300:
        raise ValueError("authority lock timeout must be finite and between 0 and 300 seconds")

    lock_path = path.expanduser().absolute()
    _assert_lock_authority(lock_path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    fd: int | None = None
    posix_locked = False
    windows_mutex = None
    try:
        fd = os.open(lock_path, flags, 0o600)
        opened_stat = os.fstat(fd)
        if opened_stat.st_size == 0:
            os.write(fd, b"\0")
            os.fsync(fd)
        _assert_lock_authority(lock_path)
        current_stat = lock_path.stat()
        if not _same_file_identity(opened_stat, current_stat):
            raise AuthorityLockError("authority lock identity changed during open")

        if os.name == "nt":
            windows_mutex = _acquire_windows_mutex(lock_path, timeout)
        else:
            deadline = time.monotonic() + timeout
            while not _try_posix_lock(fd):
                if time.monotonic() >= deadline:
                    raise AuthorityLockError("timed out waiting for authority lock")
                time.sleep(_RETRY_SECONDS)
            posix_locked = True

        _assert_lock_authority(lock_path)
        current_stat = lock_path.stat()
        if not _same_file_identity(opened_stat, current_stat):
            raise AuthorityLockError("authority lock identity changed before critical section")

        yield

        _assert_lock_authority(lock_path)
        current_stat = lock_path.stat()
        if not _same_file_identity(opened_stat, current_stat):
            raise AuthorityLockError("authority lock identity changed during critical section")
    finally:
        cleanup_error: Exception | None = None
        if windows_mutex is not None:
            kernel32, handle = windows_mutex
            try:
                _release_windows_mutex(kernel32, handle)
            except Exception as exc:  # pragma: no cover - exceptional OS cleanup path
                cleanup_error = exc
        if fd is not None:
            if posix_locked:
                try:
                    _unlock_posix(fd)
                except Exception as exc:  # pragma: no cover - exceptional OS cleanup path
                    if cleanup_error is None:
                        cleanup_error = exc
            try:
                os.close(fd)
            except Exception as exc:  # pragma: no cover - exceptional OS cleanup path
                if cleanup_error is None:
                    cleanup_error = exc
        if cleanup_error is not None:
            raise cleanup_error
