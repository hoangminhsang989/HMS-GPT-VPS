from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
from tempfile import NamedTemporaryFile


CRYPTPROTECT_UI_FORBIDDEN = 0x1


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


def protect_bytes(data: bytes, *, description: str = "HMS-GPT-VPS transient secret") -> bytes:
    """Protect bytes to the current Windows user with DPAPI and no UI."""
    _require_windows()
    if not data:
        raise ValueError("secret data must not be empty")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(DataBlob),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    source, source_buffer = _input_blob(data)
    _ = source_buffer
    output = DataBlob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(source),
        description,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output),
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "CryptProtectData failed")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        if output.pbData:
            kernel32.LocalFree(ctypes.cast(output.pbData, wintypes.HLOCAL))


def unprotect_bytes(data: bytes) -> bytes:
    """Decrypt bytes previously protected for the current Windows user."""
    _require_windows()
    if not data:
        raise ValueError("protected data must not be empty")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DataBlob),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DataBlob),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

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
            kernel32.LocalFree(ctypes.cast(output.pbData, wintypes.HLOCAL))


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
