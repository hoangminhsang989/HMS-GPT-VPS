from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import MutableMapping

from .bridge_agent_transport_qualification import BridgeAgentTransportQualificationRequest
from .bridge_composite_agent_transport_qualification import (
    qualify_authenticated_agent_transport_with_secure_tunnel,
)
from .powershell_direct import PowerShellDirectCredential
from .qualification_file_authority import write_json_create_only

BOOTSTRAP_USERNAME_ENV = "HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME"
BOOTSTRAP_PASSWORD_ENV = "HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD"
_MAX_PROOF_BYTES = 64 * 1024
_PROOF_SCHEMA_VERSION = 1
_RESULT_KEYS = frozenset(
    {
        "ready",
        "status",
        "service_sid",
        "service_state",
        "service_start_mode",
        "runtime_process_id",
        "tunnel_process_id",
        "tunnel_executable_sha256",
        "tunnel_readiness_body_class",
        "secure_mcp_tunnel_ready_during_transport",
        "tunnel_stable_across_authenticated_transport",
        "agent_process_id",
        "agent_device_id",
        "agent_boot_id",
        "agent_connection_epoch",
        "authenticated_hello_proven",
        "authenticated_heartbeat_proven",
        "authenticated_poll_proven",
        "authenticated_result_proven",
        "authenticated_agent_transport_proven",
        "qualification_action",
        "qualification_request_id",
        "qualification_result_outcome",
        "listeners_absent_after_stop",
        "full_bridge_command_flow_proven",
        "bootstrap_retired",
        "pairing_ready",
        "automatic_start_enabled",
    }
)


class BridgeCompositeAgentTransportRunnerError(RuntimeError):
    pass


def require_windows_administrator() -> None:
    if os.name != "nt":
        raise OSError("composite Agent transport qualification requires Windows")
    try:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception as exc:
        raise BridgeCompositeAgentTransportRunnerError(
            "could not determine Windows Administrator authority"
        ) from exc
    if not elevated:
        raise PermissionError(
            "composite Agent transport qualification requires Administrator"
        )


def load_bootstrap_credential_from_environment(
    environment: MutableMapping[str, str] | None = None,
) -> PowerShellDirectCredential:
    env = os.environ if environment is None else environment
    username = env.pop(BOOTSTRAP_USERNAME_ENV, "")
    password = env.pop(BOOTSTRAP_PASSWORD_ENV, "")
    if not isinstance(username, str) or not username.strip():
        raise BridgeCompositeAgentTransportRunnerError(
            f"{BOOTSTRAP_USERNAME_ENV} is required"
        )
    if not isinstance(password, str) or not password:
        raise BridgeCompositeAgentTransportRunnerError(
            f"{BOOTSTRAP_PASSWORD_ENV} is required"
        )
    credential = PowerShellDirectCredential(username=username, password=password)
    credential.validate()
    return credential


def validate_composite_agent_transport_result(
    result: dict[str, object],
) -> dict[str, object]:
    if not isinstance(result, dict) or frozenset(result) != _RESULT_KEYS:
        raise BridgeCompositeAgentTransportRunnerError(
            "composite Agent transport result schema is invalid"
        )
    for key in (
        "ready",
        "secure_mcp_tunnel_ready_during_transport",
        "tunnel_stable_across_authenticated_transport",
        "authenticated_hello_proven",
        "authenticated_heartbeat_proven",
        "authenticated_poll_proven",
        "authenticated_result_proven",
        "authenticated_agent_transport_proven",
        "listeners_absent_after_stop",
    ):
        if result.get(key) is not True:
            raise BridgeCompositeAgentTransportRunnerError(
                f"composite Agent transport did not prove {key}"
            )
    for key in (
        "full_bridge_command_flow_proven",
        "bootstrap_retired",
        "pairing_ready",
        "automatic_start_enabled",
    ):
        if result.get(key) is not False:
            raise BridgeCompositeAgentTransportRunnerError(
                f"composite Agent transport escaped staged proof boundary: {key}"
            )
    if result.get("status") != "AUTHENTICATED_AGENT_TRANSPORT_WITH_TUNNEL_QUALIFIED_STOPPED":
        raise BridgeCompositeAgentTransportRunnerError(
            "composite Agent transport status is invalid"
        )
    if result.get("service_state") != "Stopped" or result.get("service_start_mode") != "Manual":
        raise BridgeCompositeAgentTransportRunnerError(
            "composite Agent transport did not return HMSBridge to Stopped/Manual"
        )
    if result.get("qualification_action") != "git.status":
        raise BridgeCompositeAgentTransportRunnerError(
            "composite Agent transport qualification action differs"
        )
    for key in ("runtime_process_id", "tunnel_process_id", "agent_process_id", "agent_connection_epoch"):
        value = result.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BridgeCompositeAgentTransportRunnerError(
                f"composite Agent transport has invalid {key}"
            )
    return dict(result)


def run_composite_agent_transport_qualification(
    *,
    proof_path: Path,
    environment: MutableMapping[str, str] | None = None,
) -> dict[str, object]:
    if not isinstance(proof_path, Path):
        raise TypeError("proof_path must be pathlib.Path")
    require_windows_administrator()
    credential = load_bootstrap_credential_from_environment(environment)
    request = BridgeAgentTransportQualificationRequest(guest_credential=credential)
    request.validate()
    result = validate_composite_agent_transport_result(
        qualify_authenticated_agent_transport_with_secure_tunnel(request)
    )
    proof = {
        "schema_version": _PROOF_SCHEMA_VERSION,
        "qualification": "R002F_AUTHENTICATED_AGENT_TRANSPORT_WITH_SECURE_TUNNEL",
        "status": result["status"],
        "result": result,
    }
    write_json_create_only(
        proof_path,
        proof,
        max_bytes=_MAX_PROOF_BYTES,
        label="HMSBridge composite Agent transport qualification proof",
    )
    return proof
