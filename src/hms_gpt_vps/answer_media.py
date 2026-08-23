from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile
import hashlib

import pycdlib


@dataclass(frozen=True)
class AnswerMediaArtifact:
    path: Path
    sha256: str
    size: int


def _sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_answer_media_iso(output_path: Path, autounattend_xml: str) -> AnswerMediaArtifact:
    """Create a tiny secondary ISO containing root `Autounattend.xml`.

    The Windows product ISO remains unchanged. Windows Setup can discover the
    answer file from a second CD/DVD. The output is verified by reopening the
    ISO and reading the Joliet path before it atomically replaces the target.
    """
    if output_path.suffix.lower() != ".iso":
        raise ValueError("answer media output must use .iso extension")
    if not autounattend_xml.strip():
        raise ValueError("Autounattend.xml content is required")
    if "<unattend" not in autounattend_xml:
        raise ValueError("answer file does not appear to contain an unattend document")

    payload = autounattend_xml.encode("utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with NamedTemporaryFile(
        dir=output_path.parent,
        prefix=output_path.stem + ".",
        suffix=".tmp.iso",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)

    try:
        temp_path.unlink(missing_ok=True)
        iso = pycdlib.PyCdlib()
        try:
            iso.new(interchange_level=3, joliet=3, vol_ident="HMSANSWER")
            iso.add_fp(
                BytesIO(payload),
                len(payload),
                iso_path="/AUTOUNAT.XML;1",
                joliet_path="/Autounattend.xml",
            )
            iso.write(str(temp_path))
        finally:
            iso.close()

        verify = pycdlib.PyCdlib()
        extracted = BytesIO()
        try:
            verify.open(str(temp_path))
            verify.get_file_from_iso_fp(extracted, joliet_path="/Autounattend.xml")
        finally:
            verify.close()

        if extracted.getvalue() != payload:
            raise RuntimeError("answer media ISO readback mismatch")

        temp_path.replace(output_path)
        return AnswerMediaArtifact(
            path=output_path,
            sha256=_sha256(output_path),
            size=output_path.stat().st_size,
        )
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
