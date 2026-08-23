from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
from tempfile import NamedTemporaryFile


CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4


class DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class DpapiUnavailableError(OSError):
    pass


def _require_windows() -> None:
    if os.name != "nt":
        raise DpapiUnavailableError("Windows DPAPI is available only on Windows")


def _input_blob(data: bytes) -> tuple[DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(data)
    blob = DataBlob(
        len(data),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer


def _configure_native() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL

    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DataBlob),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL

    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def _protect_bytes(data: bytes, *, description: str, flags: int) -> bytes:
    _require_windows()
    if not data:
        raise ValueError("secret data must not be empty")

    crypt32, kernel32 = _configure_native()
    source, source_buffer = _input_blob(data)
    _ = source_buffer
    output = DataBlob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(source),
        description,
        None,
        None,
        None,
        flags,
        ctypes.byref(output),
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptProtectData failed")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if output.pbData:
            kernel32.LocalFree(ctypes.cast(output.pbData, ctypes.c_void_p))


def protect_bytes(data: bytes, *, description: str = "HMS-GPT-VPS transient secret") -> bytes:
    """Protect bytes to the current Windows user with DPAPI and no UI.

    This keeps the historical/default HMS behavior unchanged. Use the explicit
    `protect_bytes_machine` API only for a secret that must be decrypted by a
    different Windows identity on the same managed machine, and pair that scope
    with a restrictive filesystem ACL.
    """
    return _protect_bytes(
        data,
        description=description,
        flags=CRYPTPROTECT_UI_FORBIDDEN,
    )


def protect_bytes_machine(
    data: bytes,
    *,
    description: str = "HMS-GPT-VPS machine secret",
) -> bytes:
    """Protect bytes to the local Windows machine with DPAPI and no UI.

    Machine scope intentionally does not make the ciphertext private from every
    local Windows identity. Callers must store the protected blob behind a
    restrictive ACL. HMS uses this only when bootstrap and the long-lived Agent
    service run under different Windows identities on the same managed guest.
    """
    return _protect_bytes(
        data,
        description=description,
        flags=CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
    )


def unprotect_bytes(data: bytes) -> bytes:
    """Decrypt a DPAPI blob available to the current identity/machine scope."""
    _require_windows()
    if not data:
        raise ValueError("protected data must not be empty")

    crypt32, kernel32 = _configure_native()
    source, source_buffer = _input_blob(data)
    _ = source_buffer
    output = DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output),
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptUnprotectData failed")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if output.pbData:
            kernel32.LocalFree(ctypes.cast(output.pbData, ctypes.c_void_p))


class DpapiSecretStore:
    """Atomic current-user DPAPI storage for short-lived provisioning secrets."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def save_text(self, secret: str) -> None:
        if not secret:
            raise ValueError("secret must not be empty")
        protected = protect_bytes(secret.encode("utf-8"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            "wb",
            dir=self.path.parent,
            prefix=self.path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(protected)
            temp_path = Path(handle.name)
        temp_path.replace(self.path)

    def load_text(self) -> str:
        protected = self.path.read_bytes()
        return unprotect_bytes(protected).decode("utf-8")

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
