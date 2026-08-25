from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import hashlib
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO

import pycdlib


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


@dataclass(frozen=True)
class AnswerMediaArtifact:
    path: Path
    sha256: str
    size: int


def _lexical_absolute(path: Path) -> Path:
    return path.expanduser().absolute()


def _path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = _lexical_absolute(path)
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


def _target_matches_identity(path: Path, opened_stat: os.stat_result) -> bool:
    authority = _lexical_absolute(path)
    if _path_chain_has_redirect(authority):
        return False
    try:
        current = authority.stat()
    except FileNotFoundError:
        return False
    return authority.is_file() and _same_file_identity(opened_stat, current)


def _require_output_authority(path: Path) -> Path:
    authority = _lexical_absolute(path)
    if _path_chain_has_redirect(authority):
        raise PermissionError(
            "answer-media output path must not traverse a link or reparse point"
        )
    if not authority.parent.is_dir():
        raise FileNotFoundError("answer-media output parent directory does not exist")
    if authority.exists() and not authority.is_file():
        raise PermissionError("answer-media output target must be a regular file")
    return authority


def _sha256_open_file(handle: BinaryIO, chunk_size: int = 1024 * 1024) -> str:
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    handle.seek(0)
    digest = hashlib.sha256()
    while True:
        chunk = handle.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def build_answer_media_iso(output_path: Path, autounattend_xml: str) -> AnswerMediaArtifact:
    """Create a tiny secondary ISO containing root `Autounattend.xml`.

    The Windows product ISO remains unchanged. The new ISO is mastered, hashed,
    and verified through one process-owned temporary file handle. Only after the
    exact opened file has passed readback verification is it atomically renamed
    over the target. The returned digest and size therefore describe the bytes
    that were verified before publication rather than a later pathname reopen.
    """
    if output_path.suffix.lower() != ".iso":
        raise ValueError("answer media output must use .iso extension")
    if not autounattend_xml.strip():
        raise ValueError("Autounattend.xml content is required")
    if "<unattend" not in autounattend_xml:
        raise ValueError("answer file does not appear to contain an unattend document")

    payload = autounattend_xml.encode("utf-8")
    output_authority = _lexical_absolute(output_path)
    if _path_chain_has_redirect(output_authority.parent):
        raise PermissionError(
            "answer-media output parent must not traverse a link or reparse point"
        )
    output_authority.parent.mkdir(parents=True, exist_ok=True)
    output_authority = _require_output_authority(output_authority)

    temp_path: Path | None = None
    opened_stat: os.stat_result | None = None
    published = False
    sha256: str | None = None
    size: int | None = None
    payload_fp = BytesIO(payload)
    iso = pycdlib.PyCdlib()
    try:
        iso.new(interchange_level=3, joliet=3, vol_ident="HMSANSWER")
        iso.add_fp(
            payload_fp,
            len(payload),
            iso_path="/AUTOUNAT.XML;1",
            joliet_path="/Autounattend.xml",
        )

        with NamedTemporaryFile(
            mode="w+b",
            dir=output_authority.parent,
            prefix=output_authority.stem + ".",
            suffix=".tmp.iso",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            opened_stat = os.fstat(handle.fileno())
            if not _target_matches_identity(temp_path, opened_stat):
                raise RuntimeError("answer-media temp authority changed after creation")

            iso.write_fp(handle)
            handle.flush()
            os.fsync(handle.fileno())
            current_stat = os.fstat(handle.fileno())
            if not _same_file_identity(opened_stat, current_stat):
                raise RuntimeError("answer-media temp opened-file identity changed")
            if current_stat.st_size <= 0:
                raise RuntimeError("answer-media ISO is empty")
            if not _target_matches_identity(temp_path, opened_stat):
                raise RuntimeError("answer-media temp authority changed during mastering")

            size = current_stat.st_size
            sha256 = _sha256_open_file(handle)

            handle.seek(0)
            verify = pycdlib.PyCdlib()
            extracted = BytesIO()
            try:
                verify.open_fp(handle)
                verify.get_file_from_iso_fp(
                    extracted,
                    joliet_path="/Autounattend.xml",
                )
            finally:
                verify.close()

            if extracted.getvalue() != payload:
                raise RuntimeError("answer media ISO readback mismatch")
            if handle.closed:
                raise RuntimeError("answer-media verifier closed the owned temp file")
            final_stat = os.fstat(handle.fileno())
            if not _same_file_identity(opened_stat, final_stat):
                raise RuntimeError("answer-media temp identity changed during verification")
            if final_stat.st_size != size:
                raise RuntimeError("answer-media ISO size changed during verification")
            if not _target_matches_identity(temp_path, opened_stat):
                raise RuntimeError("answer-media temp authority changed during verification")

        if temp_path is None or opened_stat is None or sha256 is None or size is None:
            raise RuntimeError("answer-media publication authority is incomplete")
        if not _target_matches_identity(temp_path, opened_stat):
            raise RuntimeError("answer-media temp authority changed before publication")
        _require_output_authority(output_authority)
        temp_path.replace(output_authority)
        if not _target_matches_identity(output_authority, opened_stat):
            raise RuntimeError("answer-media output authority changed during publication")
        published = True
    finally:
        iso.close()
        payload_fp.close()
        if (
            not published
            and temp_path is not None
            and opened_stat is not None
            and _target_matches_identity(temp_path, opened_stat)
        ):
            temp_path.unlink(missing_ok=True)

    if sha256 is None or size is None or opened_stat is None:
        raise RuntimeError("answer-media artifact evidence is unavailable")
    if not _target_matches_identity(output_authority, opened_stat):
        raise RuntimeError("answer-media output authority changed before return")
    return AnswerMediaArtifact(path=output_path, sha256=sha256, size=size)
