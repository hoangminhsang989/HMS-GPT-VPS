from __future__ import annotations

from contextlib import AbstractContextManager
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import stat

from .qualification_file_authority import path_chain_has_redirect

_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class R002FReviewedToolchainAuthorityError(RuntimeError):
    pass


def canonical_sha256(value: object, label: str = "sha256") -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise R002FReviewedToolchainAuthorityError(
            f"{label} must be canonical lowercase SHA-256 hex"
        )
    return value


def _require_regular(path: Path) -> tuple[Path, os.stat_result]:
    if not isinstance(path, Path):
        raise TypeError("reviewed Git executable must be pathlib.Path")
    authority = path.expanduser().absolute()
    if path_chain_has_redirect(authority):
        raise R002FReviewedToolchainAuthorityError(
            "reviewed Git executable path traverses a link or reparse point"
        )
    try:
        current = authority.stat()
    except FileNotFoundError as exc:
        raise R002FReviewedToolchainAuthorityError(
            "reviewed Git executable is missing"
        ) from exc
    if not authority.is_file() or not stat.S_ISREG(current.st_mode):
        raise R002FReviewedToolchainAuthorityError(
            "reviewed Git executable must be a regular file"
        )
    if current.st_size <= 0 or current.st_size > _MAX_EXECUTABLE_BYTES:
        raise R002FReviewedToolchainAuthorityError(
            "reviewed Git executable size is outside supported bounds"
        )
    return authority, current


def _digest_path(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_EXECUTABLE_BYTES:
                raise R002FReviewedToolchainAuthorityError(
                    "reviewed Git executable exceeds supported bounds"
                )
            digest.update(chunk)
    if total <= 0:
        raise R002FReviewedToolchainAuthorityError(
            "reviewed Git executable is empty"
        )
    return digest.hexdigest()


class PinnedGitExecutable(AbstractContextManager["PinnedGitExecutable"]):
    """Hold exact Git bytes stable while reviewed checkout evidence is collected."""

    def __init__(self, path: Path, expected_sha256: str) -> None:
        self.path, initial = _require_regular(path)
        self.expected_sha256 = canonical_sha256(
            expected_sha256,
            "reviewed Git executable SHA-256",
        )
        self._identity = (
            int(initial.st_dev),
            int(initial.st_ino),
            int(initial.st_size),
        )
        self._windows_handle: int | None = None
        self._fd: int | None = None
        self.observed_sha256: str | None = None

    @property
    def executable_path(self) -> str:
        return str(self.path)

    def __enter__(self) -> "PinnedGitExecutable":
        if os.name == "nt":
            self._pin_windows()
            # The Windows handle uses FILE_SHARE_READ only, so this read cannot
            # race a writer/delete replacement while the handle remains open.
            self.observed_sha256 = _digest_path(self.path)
        else:
            self._pin_posix()
            digest = hashlib.sha256()
            assert self._fd is not None
            while True:
                chunk = os.read(self._fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            os.lseek(self._fd, 0, os.SEEK_SET)
            self.observed_sha256 = digest.hexdigest()
        if self.observed_sha256 != self.expected_sha256:
            self.close()
            raise R002FReviewedToolchainAuthorityError(
                "reviewed Git executable SHA-256 differs from external authority"
            )
        self.assert_stable()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _pin_windows(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        handle = create_file(
            str(self.path),
            _GENERIC_READ,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL,
            None,
        )
        raw = int(handle) if handle is not None else 0
        if raw in {0, _INVALID_HANDLE_VALUE}:
            raise R002FReviewedToolchainAuthorityError(
                f"could not pin reviewed Git executable; Win32 error={ctypes.get_last_error()}"
            )
        self._windows_handle = raw

    def _pin_posix(self) -> None:
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        opened = os.fstat(fd)
        identity = (int(opened.st_dev), int(opened.st_ino), int(opened.st_size))
        if identity != self._identity:
            os.close(fd)
            raise R002FReviewedToolchainAuthorityError(
                "reviewed Git executable changed during pin"
            )
        self._fd = fd

    def assert_stable(self) -> None:
        if path_chain_has_redirect(self.path):
            raise R002FReviewedToolchainAuthorityError(
                "reviewed Git executable path became redirected"
            )
        _, current = _require_regular(self.path)
        identity = (
            int(current.st_dev),
            int(current.st_ino),
            int(current.st_size),
        )
        if identity != self._identity:
            raise R002FReviewedToolchainAuthorityError(
                "reviewed Git executable path identity changed while pinned"
            )

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._windows_handle is not None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle(wintypes.HANDLE(self._windows_handle))
            self._windows_handle = None


def pin_reviewed_git_executable(
    path: Path,
    expected_sha256: str,
) -> PinnedGitExecutable:
    return PinnedGitExecutable(path, expected_sha256)
