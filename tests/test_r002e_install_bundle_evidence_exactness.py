from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps import install_bundle_observe as bundle_module
from hms_gpt_vps.install_bundle_observe import InstallBundleState, observe_install_bundle
from hms_gpt_vps.windows_provisioner import WindowsVMConfig


def _observe(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> InstallBundleState:
    monkeypatch.setattr(bundle_module, "run_powershell_json", lambda *args, **kwargs: payload)
    return observe_install_bundle(
        WindowsVMConfig(),
        Path(r"C:\media\windows.iso"),
        Path(r"C:\media\answer.iso"),
    )


def test_install_bundle_rejects_truthy_string_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RuntimeError, match="windows_iso_ready must be boolean"):
        _observe(
            monkeypatch,
            {
                "windows_iso_ready": "false",
                "answer_iso_ready": True,
                "first_boot_is_windows_iso": True,
            },
        )


def test_install_bundle_rejects_unknown_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RuntimeError, match="schema is invalid"):
        _observe(
            monkeypatch,
            {
                "windows_iso_ready": True,
                "answer_iso_ready": True,
                "first_boot_is_windows_iso": True,
                "unexpected": False,
            },
        )


def test_install_bundle_rejects_missing_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RuntimeError, match="schema is invalid"):
        _observe(
            monkeypatch,
            {
                "windows_iso_ready": True,
                "answer_iso_ready": True,
            },
        )


def test_install_bundle_exact_true_evidence_is_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _observe(
        monkeypatch,
        {
            "windows_iso_ready": True,
            "answer_iso_ready": True,
            "first_boot_is_windows_iso": True,
        },
    )

    assert result == InstallBundleState(True, True, True)
    assert result.ready is True


def test_install_bundle_dataclass_rejects_non_boolean_direct_construction() -> None:
    result = InstallBundleState(
        windows_iso_ready="false",  # type: ignore[arg-type]
        answer_iso_ready=True,
        first_boot_is_windows_iso=True,
    )
    with pytest.raises(ValueError, match="windows_iso_ready"):
        result.validate()
    with pytest.raises(ValueError, match="windows_iso_ready"):
        _ = result.ready
