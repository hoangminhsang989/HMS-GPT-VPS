from __future__ import annotations

import os

import pytest

from hms_gpt_vps import powershell
from hms_gpt_vps.powershell import PowerShellError, PowerShellResult, run_powershell_json


def test_run_powershell_json_rejects_empty_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        powershell,
        "run_powershell",
        lambda *args, **kwargs: PowerShellResult(returncode=0, stdout="", stderr=""),
    )

    with pytest.raises(PowerShellError, match="result was empty"):
        run_powershell_json("[pscustomobject]@{ ok = $true }")


def test_run_powershell_json_accepts_object(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        powershell,
        "run_powershell",
        lambda *args, **kwargs: PowerShellResult(
            returncode=0,
            stdout='{"ok":true,"value":7}',
            stderr="",
        ),
    )

    assert run_powershell_json("[pscustomobject]@{ ok = $true }") == {
        "ok": True,
        "value": 7,
    }


def test_run_powershell_json_rejects_non_object(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        powershell,
        "run_powershell",
        lambda *args, **kwargs: PowerShellResult(
            returncode=0,
            stdout='[1,2,3]',
            stderr="",
        ),
    )

    with pytest.raises(PowerShellError, match="must be an object"):
        run_powershell_json("1,2,3")


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_native_powershell_json_throw_is_nonzero() -> None:
    with pytest.raises(PowerShellError, match="intentional-hms-json-failure"):
        run_powershell_json("throw 'intentional-hms-json-failure'")


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_native_powershell_json_object_round_trip() -> None:
    assert run_powershell_json(
        "[pscustomobject]@{ ok = $true; value = 11 }"
    ) == {"ok": True, "value": 11}
