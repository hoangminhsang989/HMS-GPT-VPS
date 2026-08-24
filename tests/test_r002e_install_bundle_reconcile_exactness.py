from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps import install_bundle as bundle_module
from hms_gpt_vps.install_bundle import InstallBundleObservation, reconcile_install_bundle
from hms_gpt_vps.windows_provisioner import WindowsVMConfig


WINDOWS_ISO = Path(r"C:\media\windows.iso")
ANSWER_ISO = Path(r"C:\media\answer.iso")


def _valid_payload() -> dict[str, object]:
    return {
        "changed": False,
        "windows_iso_ready": True,
        "answer_iso_ready": True,
        "windows_iso_path": str(WINDOWS_ISO),
        "answer_iso_path": str(ANSWER_ISO),
    }


def _reconcile(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> InstallBundleObservation:
    monkeypatch.setattr(bundle_module, "run_powershell_json", lambda *args, **kwargs: payload)
    return reconcile_install_bundle(WindowsVMConfig(), WINDOWS_ISO, ANSWER_ISO)


def test_install_bundle_reconcile_rejects_truthy_string_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _valid_payload()
    payload["windows_iso_ready"] = "false"

    with pytest.raises(RuntimeError, match="windows_iso_ready must be boolean"):
        _reconcile(monkeypatch, payload)


def test_install_bundle_reconcile_rejects_wrong_answer_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _valid_payload()
    payload["answer_iso_path"] = r"C:\media\other.iso"

    with pytest.raises(RuntimeError, match="answer ISO path differs"):
        _reconcile(monkeypatch, payload)


def test_install_bundle_reconcile_rejects_unknown_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _valid_payload()
    payload["unexpected"] = True

    with pytest.raises(RuntimeError, match="schema is invalid"):
        _reconcile(monkeypatch, payload)


def test_install_bundle_reconcile_accepts_exact_bound_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _reconcile(monkeypatch, _valid_payload())

    assert result.ready is True
    assert result.windows_iso_path == str(WINDOWS_ISO)
    assert result.answer_iso_path == str(ANSWER_ISO)


def test_install_bundle_observation_rejects_direct_non_boolean() -> None:
    result = InstallBundleObservation(
        windows_iso_ready="false",  # type: ignore[arg-type]
        answer_iso_ready=True,
        windows_iso_path=str(WINDOWS_ISO),
        answer_iso_path=str(ANSWER_ISO),
    )

    with pytest.raises(ValueError, match="windows_iso_ready"):
        result.validate()
