from __future__ import annotations

from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    HMS_BRIDGE_SERVICE_NAME,
    require_hms_bridge_service_sid,
)
from .bridge_windows_service_host import BRIDGE_SERVICE_FAILURE_RUNTIME_CONSTRUCTION


ERROR_SERVICE_SPECIFIC_ERROR = 1066
BRIDGE_NATIVE_SCM_PROOF_SCHEMA_VERSION = 1
_OBSERVATION_KEYS = frozenset(
    {
        "service_name",
        "state",
        "start_mode",
        "start_name",
        "path_name",
        "exit_code",
        "service_specific_exit_code",
        "service_sid",
        "service_sid_type",
        "binary_sha256",
        "listener_absent_before",
        "listener_absent_after",
        "runtime_root_absent_before",
        "runtime_root_absent_after",
    }
)


class BridgeNativeScmFailClosedError(RuntimeError):
    pass


def _require_sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise BridgeNativeScmFailClosedError(
            "Bridge native SCM binary SHA-256 evidence is invalid"
        )
    return value


def validate_bridge_native_scm_failclosed_observation(
    observation: dict[str, object],
    *,
    expected_binary_path: str,
    expected_binary_sha256: str,
) -> dict[str, object]:
    """Validate the deliberate missing-config SCM failure at runtime construction.

    The Windows service host uses service-specific code 110 while proving the
    effective HMSBridge token and changes it to 120 only after that proof returns.
    Therefore an exact 1066/120 stopped observation proves the identity phase
    completed and runtime construction then failed closed.
    """

    if not isinstance(observation, dict) or frozenset(observation) != _OBSERVATION_KEYS:
        raise BridgeNativeScmFailClosedError(
            "Bridge native SCM observation schema is invalid"
        )
    if (
        not isinstance(expected_binary_path, str)
        or not expected_binary_path
        or expected_binary_path != expected_binary_path.strip()
    ):
        raise BridgeNativeScmFailClosedError("expected_binary_path is invalid")
    expected_sha = _require_sha256(expected_binary_sha256)
    expected_command = f'"{expected_binary_path}" service'

    exact = {
        "service_name": HMS_BRIDGE_SERVICE_NAME,
        "state": "Stopped",
        "start_mode": "Manual",
        "service_sid_type": "UNRESTRICTED",
        "binary_sha256": expected_sha,
        "listener_absent_before": True,
        "listener_absent_after": True,
        "runtime_root_absent_before": True,
        "runtime_root_absent_after": True,
    }
    for key, expected in exact.items():
        if observation.get(key) != expected:
            raise BridgeNativeScmFailClosedError(
                f"Bridge native SCM observation differs at {key}"
            )

    start_name = observation.get("start_name")
    if (
        not isinstance(start_name, str)
        or start_name.casefold() != HMS_BRIDGE_SERVICE_ACCOUNT.casefold()
    ):
        raise BridgeNativeScmFailClosedError(
            "Bridge native SCM service account differs from authority"
        )
    if observation.get("path_name") != expected_command:
        raise BridgeNativeScmFailClosedError(
            "Bridge native SCM command differs from packaged binary authority"
        )
    service_sid = require_hms_bridge_service_sid(observation.get("service_sid"))
    exit_code = observation.get("exit_code")
    specific = observation.get("service_specific_exit_code")
    if (
        not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or exit_code != ERROR_SERVICE_SPECIFIC_ERROR
    ):
        raise BridgeNativeScmFailClosedError(
            "Bridge native SCM did not report ERROR_SERVICE_SPECIFIC_ERROR"
        )
    if (
        not isinstance(specific, int)
        or isinstance(specific, bool)
        or specific != BRIDGE_SERVICE_FAILURE_RUNTIME_CONSTRUCTION
    ):
        raise BridgeNativeScmFailClosedError(
            "Bridge native SCM did not fail at runtime-construction phase"
        )

    return {
        "schema_version": BRIDGE_NATIVE_SCM_PROOF_SCHEMA_VERSION,
        "ready": True,
        "service_name": HMS_BRIDGE_SERVICE_NAME,
        "service_account": HMS_BRIDGE_SERVICE_ACCOUNT,
        "service_sid": service_sid,
        "service_sid_type": "UNRESTRICTED",
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "binary_path": expected_binary_path,
        "binary_sha256": expected_sha,
        "win32_exit_code": ERROR_SERVICE_SPECIFIC_ERROR,
        "service_specific_exit_code": BRIDGE_SERVICE_FAILURE_RUNTIME_CONSTRUCTION,
        "strict_identity_phase_passed": True,
        "runtime_construction_failed_closed": True,
        "listener_absent_before": True,
        "listener_absent_after": True,
        "production_runtime_root_absent_before": True,
        "production_runtime_root_absent_after": True,
        "production_secrets_provisioned": False,
        "tls_listener_started": False,
        "pairing_ready": False,
    }
