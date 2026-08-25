from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Mapping


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def lexical_absolute(path: Path) -> Path:
    return path.expanduser().absolute()


def path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = lexical_absolute(path)
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


def _target_matches_opened_file(path: Path, opened_stat: os.stat_result) -> bool:
    if path_chain_has_redirect(path):
        return False
    try:
        current = path.stat()
    except FileNotFoundError:
        return False
    return (
        path.is_file()
        and stat.S_ISREG(current.st_mode)
        and _same_file_identity(opened_stat, current)
    )


def require_existing_directory(path: Path, *, label: str) -> Path:
    authority = lexical_absolute(path)
    if path_chain_has_redirect(authority):
        raise PermissionError(f"{label} path must not traverse a link or reparse point")
    try:
        current = authority.stat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(authority) from exc
    if not stat.S_ISDIR(current.st_mode) or not authority.is_dir():
        raise PermissionError(f"{label} must be a directory")
    return authority


def require_new_file_target(path: Path, *, label: str) -> Path:
    authority = lexical_absolute(path)
    if path_chain_has_redirect(authority):
        raise PermissionError(f"{label} path must not traverse a link or reparse point")
    if authority.exists() or authority.is_symlink():
        raise FileExistsError(f"{label} target already exists")
    parent = authority.parent
    if path_chain_has_redirect(parent):
        raise PermissionError(f"{label} parent must not traverse a link or reparse point")
    if not parent.is_dir():
        raise FileNotFoundError(f"{label} parent directory does not exist")
    return authority


def read_file_pinned(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    allow_empty: bool = False,
    expected_identity: os.stat_result | None = None,
) -> bytes:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    authority = lexical_absolute(path)
    if path_chain_has_redirect(authority):
        raise PermissionError(f"{label} path must not traverse a link or reparse point")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(authority, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise PermissionError(f"{label} must be a regular file")
        if expected_identity is not None and not _same_file_identity(opened, expected_identity):
            raise RuntimeError(f"{label} opened-file identity differs from expected authority")
        if opened.st_size > max_bytes:
            raise ValueError(f"{label} exceeds size bound")
        if not allow_empty and opened.st_size <= 0:
            raise ValueError(f"{label} must not be empty")
        if not _target_matches_opened_file(authority, opened):
            raise RuntimeError(f"{label} authority changed before read")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
            current_opened = os.fstat(handle.fileno())
            if not _same_file_identity(opened, current_opened):
                raise RuntimeError(f"{label} opened-file identity changed during read")
            if len(data) > max_bytes:
                raise ValueError(f"{label} exceeds size bound")
            if not allow_empty and not data:
                raise ValueError(f"{label} must not be empty")
            if current_opened.st_size != len(data):
                raise RuntimeError(f"{label} size changed during read")
            if not _target_matches_opened_file(authority, opened):
                raise RuntimeError(f"{label} authority changed during read")
        if not _target_matches_opened_file(authority, opened):
            raise RuntimeError(f"{label} authority changed after read")
        return data
    finally:
        os.close(fd)


def write_bytes_create_only(
    path: Path,
    data: bytes,
    *,
    max_bytes: int,
    label: str,
) -> Path:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if not data:
        raise ValueError(f"{label} must not be empty")
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds publication bound")
    target = require_new_file_target(path, label=label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd: int | None = None
    opened: os.stat_result | None = None
    created = False
    published = False
    try:
        fd = os.open(target, flags, 0o600)
        opened = os.fstat(fd)
        created = True
        if not stat.S_ISREG(opened.st_mode):
            raise PermissionError(f"{label} target is not a regular file")
        if not _target_matches_opened_file(target, opened):
            raise RuntimeError(f"{label} authority changed after create-only open")
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            if os.fstat(handle.fileno()).st_size != len(data):
                raise RuntimeError(f"{label} write size mismatch")
            if not _target_matches_opened_file(target, opened):
                raise RuntimeError(f"{label} authority changed during publication")
        if not _target_matches_opened_file(target, opened):
            raise RuntimeError(f"{label} authority changed after publication")
        readback = read_file_pinned(
            target,
            max_bytes=max_bytes,
            label=label,
            expected_identity=opened,
        )
        if readback != data:
            raise RuntimeError(f"{label} readback mismatch")
        if not _target_matches_opened_file(target, opened):
            raise RuntimeError(f"{label} authority changed during readback")
        published = True
        return target
    finally:
        if fd is not None:
            os.close(fd)
        if (
            created
            and not published
            and opened is not None
            and _target_matches_opened_file(target, opened)
        ):
            target.unlink(missing_ok=True)


def write_json_create_only(
    path: Path,
    payload: Mapping[str, object],
    *,
    max_bytes: int,
    label: str,
) -> Path:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    data = (
        json.dumps(
            dict(payload),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    return write_bytes_create_only(
        path,
        data,
        max_bytes=max_bytes,
        label=label,
    )
