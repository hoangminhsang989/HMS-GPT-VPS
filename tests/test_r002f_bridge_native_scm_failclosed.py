from __future__ import annotations

import pytest

import hms_gpt_vps.bridge_native_scm_failclosed as mod


SID = "S-1-5-80-1-2-3-4-5"
SHA = "a" * 64
BINARY = r"C:\runner\hms-bridge\hms-bridge.exe"


def observation(**overrides):
    data = {
        "service_name": "HMSBridge",
        "state": "Stopped",
        "start_mode": "Manual",
        "start_name": r"NT SERVICE\HMSBridge",
        "path_name": f'"{BINARY}" service',
        "exit_code": 1066,
        "service_specific_exit_code": 120,
        "service_sid": SID,
        "service_sid_type": "UNRESTRICTED",
        "binary_sha256": SHA,
        "listener_absent_before": True,
        "listener_absent_after": True,
        "runtime_root_absent_before": True,
        "runtime_root_absent_after": True,
    }
    data.update(overrides)
    return data


def test_exact_runtime_construction_failure_proves_identity_phase():
    proof = mod.validate_bridge_native_scm_failclosed_observation(
        observation(),
        expected_binary_path=BINARY,
        expected_binary_sha256=SHA,
    )
    assert proof["strict_identity_phase_passed"] is True
    assert proof["runtime_construction_failed_closed"] is True
    assert proof["tls_listener_started"] is False
    assert proof["pairing_ready"] is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"exit_code": 0},
        {"service_specific_exit_code": 110},
        {"service_specific_exit_code": 125},
        {"state": "Running"},
        {"start_mode": "Auto"},
        {"listener_absent_after": False},
        {"runtime_root_absent_after": False},
    ],
)
def test_drift_is_rejected(overrides):
    with pytest.raises(mod.BridgeNativeScmFailClosedError):
        mod.validate_bridge_native_scm_failclosed_observation(
            observation(**overrides),
            expected_binary_path=BINARY,
            expected_binary_sha256=SHA,
        )


def test_wrong_command_is_rejected():
    with pytest.raises(mod.BridgeNativeScmFailClosedError):
        mod.validate_bridge_native_scm_failclosed_observation(
            observation(path_name=f'"{BINARY}"'),
            expected_binary_path=BINARY,
            expected_binary_sha256=SHA,
        )


def test_invalid_sid_is_rejected():
    with pytest.raises(Exception):
        mod.validate_bridge_native_scm_failclosed_observation(
            observation(service_sid="S-1-5-32-544"),
            expected_binary_path=BINARY,
            expected_binary_sha256=SHA,
        )
