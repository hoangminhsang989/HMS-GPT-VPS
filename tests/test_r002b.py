from pathlib import Path

from hms_gpt_vps.elevation import ElevationDecision, ElevationRequest, evaluate_elevation
from hms_gpt_vps.reboot_resume import ResumeState, ResumeStateStore
from hms_gpt_vps.windows_image import WindowsImage, sha256_file


def test_elevation_requires_explicit_approval() -> None:
    decision = evaluate_elevation(ElevationRequest(reason="Enable Hyper-V"))
    assert decision is ElevationDecision.REQUIRE_APPROVAL


def test_elevation_allows_approved_request() -> None:
    decision = evaluate_elevation(
        ElevationRequest(reason="Enable Hyper-V", explicitly_approved=True)
    )
    assert decision is ElevationDecision.APPROVED


def test_resume_state_round_trip(tmp_path: Path) -> None:
    store = ResumeStateStore(tmp_path / "resume.json")
    expected = ResumeState(
        revision="R002B",
        phase="reboot_required",
        instance_id="HMS-GPT-VPS-01",
        reason="Hyper-V feature enabled",
    )
    store.save(expected)
    assert store.load() == expected
    store.clear()
    assert store.load() is None


def test_windows_iso_hash_validation(tmp_path: Path) -> None:
    iso = tmp_path / "windows.iso"
    iso.write_bytes(b"test-image")
    digest = sha256_file(iso)
    WindowsImage(iso, digest).validate()


def test_windows_image_rejects_non_iso(tmp_path: Path) -> None:
    image = tmp_path / "windows.img"
    image.write_bytes(b"x")
    try:
        WindowsImage(image).validate()
    except ValueError:
        pass
    else:
        raise AssertionError("non-ISO image must be rejected")
