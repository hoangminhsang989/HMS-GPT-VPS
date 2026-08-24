from __future__ import annotations

from dataclasses import dataclass

import pytest

from hms_gpt_vps import hyperv_probe as probe_module


@dataclass
class _Completed:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def _run_with_payload(monkeypatch: pytest.MonkeyPatch, payload: str):
    monkeypatch.setattr(probe_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        probe_module.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(stdout=payload),
    )
    return probe_module.probe_hyperv_host()


def test_hyperv_host_probe_accepts_exact_boolean_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run_with_payload(
        monkeypatch,
        '{"hyperv_available":true,"hyperv_enabled":true,'
        '"virtualization_firmware_enabled":true,"restart_required":false}',
    )
    assert result.state.ready is True


def test_hyperv_host_probe_rejects_truthy_string_boolean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RuntimeError, match="hyperv_enabled.*boolean"):
        _run_with_payload(
            monkeypatch,
            '{"hyperv_available":true,"hyperv_enabled":"false",'
            '"virtualization_firmware_enabled":true,"restart_required":false}',
        )


def test_hyperv_host_probe_rejects_unknown_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RuntimeError, match="schema"):
        _run_with_payload(
            monkeypatch,
            '{"hyperv_available":true,"hyperv_enabled":true,'
            '"virtualization_firmware_enabled":true,"restart_required":false,'
            '"unexpected":false}',
        )


def test_hyperv_host_probe_rejects_missing_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RuntimeError, match="schema"):
        _run_with_payload(
            monkeypatch,
            '{"hyperv_available":true,"hyperv_enabled":true,'
            '"virtualization_firmware_enabled":true}',
        )


def test_hyperv_host_probe_rejects_invalid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RuntimeError, match="invalid JSON"):
        _run_with_payload(monkeypatch, "not-json")
