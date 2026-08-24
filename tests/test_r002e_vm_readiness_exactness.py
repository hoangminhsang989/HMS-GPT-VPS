from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from hms_gpt_vps import vm_readiness as vm_readiness_module
from hms_gpt_vps.vm_readiness import VMReadiness, probe_vm_readiness


def _completed(payload: object, *, returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        returncode=returncode,
        stdout=json.dumps(payload),
        stderr="",
    )


def test_vm_readiness_rejects_truthy_string_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        vm_readiness_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"exists": "false", "state": None, "heartbeat": None}
        ),
    )

    with pytest.raises(RuntimeError, match="exists evidence must be boolean"):
        probe_vm_readiness("HMS-GPT-VPS-01")


def test_vm_readiness_rejects_unknown_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        vm_readiness_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {
                "exists": True,
                "state": "Running",
                "heartbeat": "OK",
                "unexpected": True,
            }
        ),
    )

    with pytest.raises(RuntimeError, match="schema is invalid"):
        probe_vm_readiness("HMS-GPT-VPS-01")


def test_vm_readiness_rejects_non_string_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        vm_readiness_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"exists": True, "state": 1, "heartbeat": "OK"}
        ),
    )

    with pytest.raises(RuntimeError, match="state evidence"):
        probe_vm_readiness("HMS-GPT-VPS-01")


def test_vm_readiness_rejects_absent_vm_with_positive_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        vm_readiness_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"exists": False, "state": "Running", "heartbeat": "OK"}
        ),
    )

    with pytest.raises(RuntimeError, match="contradictory"):
        probe_vm_readiness("HMS-GPT-VPS-01")


def test_vm_readiness_accepts_exact_running_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        vm_readiness_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"exists": True, "state": "Running", "heartbeat": "OK"}
        ),
    )

    result = probe_vm_readiness("HMS-GPT-VPS-01")

    assert result == VMReadiness(True, "Running", "OK", True)


@pytest.mark.parametrize("timeout", [True, 0, 301, 1.5])
def test_vm_readiness_rejects_invalid_timeout(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        probe_vm_readiness("HMS-GPT-VPS-01", timeout)  # type: ignore[arg-type]


def test_vm_readiness_command_failure_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        vm_readiness_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed({}, returncode=1),
    )

    assert probe_vm_readiness("HMS-GPT-VPS-01") == VMReadiness(False, None, None, False)
