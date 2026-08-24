from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import time
from typing import Iterator


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_DEFAULT_TIMEOUT_SECONDS = 15.0
_RETRY_SECONDS = 0.05


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


def _try_lock(fd: int) -> bool:
    os.lseek(fd, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock(fd: int) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def exclusive_authority_lock(
    path: Path,
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> Iterator[None]:
    """Serialize one authority mutation without stale lock ownership after crash.

    The file is only a stable rendezvous inode; ownership is the OS advisory
    lock held on its open descriptor. A crashed process therefore releases the
    lock automatically. The rendezvous file is never deleted, and its lexical
    identity is rechecked before entering and after leaving the critical section
    so a substituted lock path fails closed instead of creating a second lock
    domain silently.
    """

    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
        raise TypeError("authority lock timeout must be numeric")
    if timeout_seconds <= 0 or timeout_seconds > 300:
        raise ValueError("authority lock timeout must be between 0 and 300 seconds")

    lock_path = path.expanduser().absolute()
    _assert_lock_authority(lock_path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    fd: int | None = None
    locked = False
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

        deadline = time.monotonic() + float(timeout_seconds)
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise AuthorityLockError("timed out waiting for authority lock")
            time.sleep(_RETRY_SECONDS)
        locked = True

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
        if fd is not None:
            if locked:
                _unlock(fd)
            os.close(fd)
