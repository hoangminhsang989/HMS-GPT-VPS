from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import MutableMapping

from .bridge_activation_qualification import BridgeActivationQualificationRequest
from .bridge_composite_activation_qualification import (
    qualify_hms_bridge_composite_activation_probe,
)
from .powershell_direct import PowerShellDirectCredential
from .qualification_file_authority import read_file_pinned, write_json_create_only

BOOTSTRAP_USERNAME_ENV = "HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME"
BOOTSTRAP_PASSWORD_ENV = "HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD"
_MAX_TRUST_ROOT_BYTES = 256 * 1024
_MAX_PROOF_BYTES = 64 * 1024
_PROOF_SCHEMA_VERSION = 1
_RESULT_KEYS = frozenset(
    {
        "ready",
        "status",
        "service_sid",
        "service_state",
        "service_start_mode",
        "service_runtime_ready_proven",
        "tls_listener_ready_during_probe",
        "mcp_listener_ready_during_probe",
        "secure_mcp_tunnel_ready_during_probe",
        "runtime_process_id",
        "tunnel_process_id",
        "tunnel_executable_sha256",
        "tunnel_readiness_body_class",
        "tunnel_stable_across_managed_guest_probe",
        "live_managed_guest_tls_proven",
        "server_certificate_sha256",
        "vm_id",
        "bridge_origin",
        "listeners_absent_after_stop",
        "authenticated_agent_transport_proven",
        "full_bridge_command_flow_proven",
        "bootstrap_retired",
        "pairing_ready",
        "automatic_start_enabled",
    }
)


class BridgeCompositeActivationRunnerError(RuntimeError):
    pass


def require_windows_administrator() -> None:
    if os.name != "nt":
        raise OSError("composite HMSBridge activation qualification requires Windows")
    try:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception as exc:
        raise BridgeCompositeActivationRunnerError(
            "could not determine Windows Administrator authority"
        ) from exc
    if not elevated:
        raise PermissionError(
            "composite HMSBridge activation qualification requires Administrator"
        )


def load_bootstrap_credential_from_environment(
    environment: MutableMapping[str, str] | None = None,
) -> PowerShellDirectCredential:
    env = os.environ if environment is None else environment
    username = env.pop(BOOTSTRAP_USERNAME_ENV, "")
    password = env.pop(BOOTSTRAP_PASSWORD_ENV, "")
    if not isinstance(username, str) or not username.strip():
        raise BridgeCompositeActivationRunnerError(
            f"{BOOTSTRAP_USERNAME_ENV} is required"
        )
    if not isinstance(password, str) or not password:
        raise BridgeCompositeActivationRunnerError(
            f"{BOOTSTRAP_PASSWORD_ENV} is required"
        )
    credential = PowerShellDirectCredential(
        username=username,
        password=password,
    )
    credential.validate()
    return credential


def validate_composite_activation_result(
    result: dict[str, object],
) -> dict[str, object]:
    if not isinstance(result, dict) or frozenset(result) != _RESULT_KEYS:
        raise BridgeCompositeActivationRunnerError(
            "composite activation result schema is invalid"
        )
    required_true = (
        "ready",
        "service_runtime_ready_proven",
        "tls_listener_ready_during_probe",
        "mcp_listener_ready_during_probe",
        "secure_mcp_tunnel_ready_during_probe",
        "tunnel_stable_across_managed_guest_probe",
        "live_managed_guest_tls_proven",
        "listeners_absent_after_stop",
    )
    for key in required_true:
        if result.get(key) is not True:
            raise BridgeCompositeActivationRunnerError(
                f"composite activation result did not prove {key}"
            )
    required_false = (
        "authenticated_agent_transport_proven",
        "full_bridge_command_flow_proven",
        "bootstrap_retired",
        "pairing_ready",
        "automatic_start_enabled",
    )
    for key in required_false:
        if result.get(key) is not False:
            raise BridgeCompositeActivationRunnerError(
                f"composite activation result escaped staged proof boundary: {key}"
            )
    if result.get("status") != "QUALIFIED_STOPPED":
        raise BridgeCompositeActivationRunnerError(
            "composite activation result status is invalid"
        )
    if result.get("service_state") != "Stopped" or result.get("service_start_mode") != "Manual":
        raise BridgeCompositeActivationRunnerError(
            "composite activation result did not return HMSBridge to Stopped/Manual"
        )
    for key in ("runtime_process_id", "tunnel_process_id"):
        value = result.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BridgeCompositeActivationRunnerError(
                f"composite activation result has invalid {key}"
            )
    return dict(result)


def run_composite_activation_qualification(
    *,
    trust_root_certificate_path: Path,
    proof_path: Path,
    environment: MutableMapping[str, str] | None = None,
) -> dict[str, object]:
    if not isinstance(trust_root_certificate_path, Path):
        raise TypeError("trust_root_certificate_path must be pathlib.Path")
    if not isinstance(proof_path, Path):
        raise TypeError("proof_path must be pathlib.Path")
    require_windows_administrator()
    credential = load_bootstrap_credential_from_environment(environment)
    trust_root = read_file_pinned(
        trust_root_certificate_path,
        max_bytes=_MAX_TRUST_ROOT_BYTES,
        label="managed guest trust-root certificate",
        allow_empty=False,
    )
    request = BridgeActivationQualificationRequest(
        guest_credential=credential,
        trust_root_certificate_pem=trust_root,
    )
    request.validate()
    result = validate_composite_activation_result(
        qualify_hms_bridge_composite_activation_probe(request)
    )
    proof = {
        "schema_version": _PROOF_SCHEMA_VERSION,
        "qualification": "R002F_HMSBRIDGE_COMPOSITE_ACTIVATION",
        "status": "QUALIFIED_STOPPED",
        "result": result,
    }
    write_json_create_only(
        proof_path,
        proof,
        max_bytes=_MAX_PROOF_BYTES,
        label="HMSBridge composite activation qualification proof",
    )
    return proof
