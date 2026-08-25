from __future__ import annotations

from io import BytesIO
import hashlib
from pathlib import Path

import pycdlib
import pytest

from hms_gpt_vps.answer_media import (
    _target_matches_identity,
    build_answer_media_iso,
)
from hms_gpt_vps.unattend import UnattendConfig, generate_unattend


def _xml(computer_name: str) -> str:
    return generate_unattend(UnattendConfig(computer_name=computer_name))


def _extract(output: Path) -> str:
    iso = pycdlib.PyCdlib()
    extracted = BytesIO()
    try:
        iso.open(str(output))
        iso.get_file_from_iso_fp(extracted, joliet_path="/Autounattend.xml")
    finally:
        iso.close()
    return extracted.getvalue().decode("utf-8")


def test_answer_media_preserves_overwrite_semantics_with_verified_bytes(
    tmp_path: Path,
) -> None:
    output = tmp_path / "answer.iso"
    first_xml = _xml("HMSVPS01")
    second_xml = _xml("HMSVPS02")

    first = build_answer_media_iso(output, first_xml)
    assert _extract(output) == first_xml
    assert first.sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert first.size == output.stat().st_size

    second = build_answer_media_iso(output, second_xml)
    assert _extract(output) == second_xml
    assert second.sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert second.size == output.stat().st_size


def test_answer_media_uses_file_object_master_and_verify_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _forbid_path_api(*args: object, **kwargs: object) -> None:
        raise AssertionError("path-based PyCdlib API must not be used by answer-media builder")

    monkeypatch.setattr(pycdlib.PyCdlib, "write", _forbid_path_api)
    monkeypatch.setattr(pycdlib.PyCdlib, "open", _forbid_path_api)

    output = tmp_path / "answer.iso"
    artifact = build_answer_media_iso(output, _xml("HMSVPS01"))
    assert artifact.path == output
    assert artifact.size > 0


def test_answer_media_rejects_symlinked_output_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit creating directory symlinks")

    with pytest.raises(PermissionError, match="link or reparse"):
        build_answer_media_iso(linked_parent / "answer.iso", _xml("HMSVPS01"))


def test_answer_media_rejects_symlink_output_target(tmp_path: Path) -> None:
    real_output = tmp_path / "real.iso"
    real_output.write_bytes(b"existing")
    linked_output = tmp_path / "answer.iso"
    try:
        linked_output.symlink_to(real_output)
    except OSError:
        pytest.skip("host does not permit creating file symlinks")

    with pytest.raises(PermissionError, match="link or reparse"):
        build_answer_media_iso(linked_output, _xml("HMSVPS01"))
    assert real_output.read_bytes() == b"existing"


def test_answer_media_identity_check_rejects_path_replacement(tmp_path: Path) -> None:
    target = tmp_path / "owned.tmp.iso"
    target.write_bytes(b"owned")
    owned_stat = target.stat()
    replacement = tmp_path / "replacement.tmp.iso"
    replacement.write_bytes(b"replacement")
    replacement.replace(target)

    assert not _target_matches_identity(target, owned_stat)
