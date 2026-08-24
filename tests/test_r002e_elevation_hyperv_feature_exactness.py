from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from hms_gpt_vps import hyperv_feature as feature_module
from hms_gpt_vps.elevation import ElevationRequest, evaluate_elevation
from hms_gpt_vps.hyperv_feature import HyperVEnableResult, enable_hyperv


def _completed(payload: object, *, returncode: int = 0, stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        returncode=returncode,
        stdout=json.dumps(payload),
        stderr=stderr,
    )


def test_elevation_rejects_truthy_string_approval() -> None:
    with pytest.raises(ValueError, match="explicitly_approved must be boolean"):
        evaluate_elevation(
            ElevationRequest(
                reason="Enable Hyper-V",
                explicitly_approved="false",  # type: ignore[arg-type]
            )
        )


def test_elevation_rejects_contradictory_approval_and_denial() -> None:
    with pytest.raises(ValueError, match="both approved and denied"):
        evaluate_elevation(
            ElevationRequest(
                reason="Enable Hyper-V",
                explicitly_approved=True,
                explicitly_denied=True,
            )
        )


def test_enable_hyperv_rejects_non_boolean_approval_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def unexpected_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(feature_module.subprocess, "run", unexpected_run)

    with pytest.raises(ValueError, match="explicitly_approved must be boolean"):
        enable_hyperv(approved="false")  # type: ignore[arg-type]

    assert called is False


def test_enable_hyperv_rejects_truthy_string_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        feature_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"enabled": "true", "restart_required": False}
        ),
    )

    with pytest.raises(RuntimeError, match="enabled evidence must be boolean"):
        enable_hyperv(approved=True)


def test_enable_hyperv_rejects_schema_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        feature_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"enabled": True, "restart_required": False, "unexpected": True}
        ),
    )

    with pytest.raises(RuntimeError, match="schema is invalid"):
        enable_hyperv(approved=True)


def test_enable_hyperv_requires_positive_readback_even_on_exit_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        feature_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"enabled": False, "restart_required": False}
        ),
    )

    with pytest.raises(RuntimeError, match="without enabled readback proof"):
        enable_hyperv(approved=True)


def test_enable_hyperv_accepts_exact_restart_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        feature_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed(
            {"enabled": True, "restart_required": True}
        ),
    )

    assert enable_hyperv(approved=True) == HyperVEnableResult(
        attempted=True,
        enabled=True,
        restart_required=True,
        message="Hyper-V feature enabled",
    )


def test_enable_hyperv_command_failure_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        feature_module.subprocess,
        "run",
        lambda *args, **kwargs: _completed({}, returncode=1, stderr="denied"),
    )

    assert enable_hyperv(approved=True) == HyperVEnableResult(
        attempted=True,
        enabled=False,
        restart_required=False,
        message="denied",
    )


@pytest.mark.parametrize("timeout", [True, 0, 1801, 1.5])
def test_enable_hyperv_rejects_invalid_timeout(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        enable_hyperv(approved=False, timeout_seconds=timeout)  # type: ignore[arg-type]
