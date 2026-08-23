from io import BytesIO
from pathlib import Path

import pycdlib

from hms_gpt_vps.answer_media import build_answer_media_iso
from hms_gpt_vps.unattend import UnattendConfig, generate_unattend


def test_answer_media_contains_root_autounattend(tmp_path: Path) -> None:
    xml = generate_unattend(UnattendConfig(computer_name="HMSVPS01"))
    output = tmp_path / "answer.iso"

    artifact = build_answer_media_iso(output, xml)

    assert artifact.path == output
    assert artifact.size > 0
    assert len(artifact.sha256) == 64

    iso = pycdlib.PyCdlib()
    extracted = BytesIO()
    try:
        iso.open(str(output))
        iso.get_file_from_iso_fp(extracted, joliet_path="/Autounattend.xml")
    finally:
        iso.close()

    assert extracted.getvalue().decode("utf-8") == xml


def test_answer_media_rejects_non_iso_target(tmp_path: Path) -> None:
    xml = generate_unattend(UnattendConfig(computer_name="HMSVPS01"))
    try:
        build_answer_media_iso(tmp_path / "answer.bin", xml)
    except ValueError as exc:
        assert ".iso" in str(exc)
    else:
        raise AssertionError("non-ISO target must be rejected")
