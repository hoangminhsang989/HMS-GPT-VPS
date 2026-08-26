from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import MutableMapping

from .bridge_external_mcp_command_flow_qualification import (
    BridgeExternalMcpCommandFlowQualificationRequest,
    qualify_external_mcp_read_with_stable_tunnel,
)
from .external_mcp_command_flow_contract import (
    canonical_git_sha1,
    canonical_sha256,
    identifier,
    qualification_path,
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
        "secure_mcp_tunnel_ready_during_external_flow",
        "tunnel_stable_across_external_flow",
        "agent_process_id",
        "agent_device_id",
        "agent_boot_id",
        "agent_connection_epoch",
        "agent_generation_stable_across_external_flow",
        "challenge_id",
        "source_commit",
        "instance_id",
        "request_id",
        "path",
        "expected_content_sha256",
        "workspace_content_size",
        "workspace_content_encoding",
        "principal_sha256",
        "pair_id",
        "session_id",
        "session_epoch",
        "agent_result_sha256",
        "authenticated_principal_control_path_proven",
        "durable_external_principal_read_proven",
        "runner_invoked_mcp",
        "runner_enqueued_agent_command",
        "secure_tunnel_generation_proven",
        "listeners_absent_after_stop",
        "mcp_adapter_invocation_proven",
        "openai_control_plane_origin_proven",
        "full_bridge_command_flow_proven",
        "bootstrap_retired",
        "pairing_ready",
        "automatic_start_enabled",
    }
)


class BridgeExternalMcpCommandFlowRunnerError(RuntimeError):
    pass


def require_windows_administrator() -> None:
    if os.name != "nt":
        raise OSError("external MCP command-flow qualification requires Windows")
    try:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception as exc:
        raise BridgeExternalMcpCommandFlowRunnerError(
            "could not determine Windows Administrator authority"
        ) from exc
    if not elevated:
        raise PermissionError(
            "external MCP command-flow qualification requires Administrator"
        )


def load_bootstrap_credential_from_environment(
    environment: MutableMapping[str, str] | None = None,
) -> PowerShellDirectCredential:
    env = os.environ if environment is None else environment
    username = env.pop(BOOTSTRAP_USERNAME_ENV, "")
    password = env.pop(BOOTSTRAP_PASSWORD_ENV, "")
    if not isinstance(username, str) or not username.strip():
        raise BridgeExternalMcpCommandFlowRunnerError(
            f"{BOOTSTRAP_USERNAME_ENV} is required"
        )
    if not isinstance(password, str) or not password:
        raise BridgeExternalMcpCommandFlowRunnerError(
            f"{BOOTSTRAP_PASSWORD_ENV} is required"
        )
    credential = PowerShellDirectCredential(username=username, password=password)
    credential.validate()
    return credential


def validate_external_mcp_command_flow_result(
    result: dict[str, object],
) -> dict[str, object]:
    if not isinstance(result, dict) or frozenset(result) != _RESULT_KEYS:
        raise BridgeExternalMcpCommandFlowRunnerError(
            "external MCP command-flow result schema is invalid"
        )
    for key in (
        "ready",
        "secure_mcp_tunnel_ready_during_external_flow",
        "tunnel_stable_across_external_flow",
        "agent_generation_stable_across_external_flow",
        "authenticated_principal_control_path_proven",
        "durable_external_principal_read_proven",
        "secure_tunnel_generation_proven",
        "listeners_absent_after_stop",
    ):
        if result.get(key) is not True:
            raise BridgeExternalMcpCommandFlowRunnerError(
                f"external MCP command-flow did not prove {key}"
            )
    for key in (
        "runner_invoked_mcp",
        "runner_enqueued_agent_command",
        "mcp_adapter_invocation_proven",
        "openai_control_plane_origin_proven",
        "full_bridge_command_flow_proven",
        "bootstrap_retired",
        "pairing_ready",
        "automatic_start_enabled",
    ):
        if result.get(key) is not False:
            raise BridgeExternalMcpCommandFlowRunnerError(
                f"external MCP command-flow escaped staged proof boundary: {key}"
            )
    if result.get("status") != "EXTERNAL_PRINCIPAL_READ_WITH_STABLE_TUNNEL_QUALIFIED_STOPPED":
        raise BridgeExternalMcpCommandFlowRunnerError(
            "external MCP command-flow status is invalid"
        )
    if result.get("service_state") != "Stopped" or result.get("service_start_mode") != "Manual":
        raise BridgeExternalMcpCommandFlowRunnerError(
            "external MCP command-flow did not return HMSBridge to Stopped/Manual"
        )
    for key in (
        "runtime_process_id",
        "tunnel_process_id",
        "agent_process_id",
        "agent_connection_epoch",
        "session_epoch",
    ):
        value = result.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BridgeExternalMcpCommandFlowRunnerError(
                f"external MCP command-flow has invalid {key}"
            )
    source_commit = result.get("source_commit")
    path = result.get("path")
    digest = result.get("expected_content_sha256")
    try:
        canonical_git_sha1(source_commit)
        qualification_path(path)
        canonical_sha256(digest, "expected_content_sha256")
        canonical_sha256(result.get("tunnel_executable_sha256"), "tunnel_executable_sha256")
        canonical_sha256(result.get("principal_sha256"), "principal_sha256")
        canonical_sha256(result.get("agent_result_sha256"), "agent_result_sha256")
        for key in (
            "challenge_id",
            "instance_id",
            "request_id",
            "pair_id",
            "session_id",
            "agent_device_id",
            "agent_boot_id",
        ):
            identifier(result.get(key), key)
    except Exception as exc:
        raise BridgeExternalMcpCommandFlowRunnerError(
            "external MCP command-flow challenge/evidence identity is invalid"
        ) from exc
    content_size = result.get("workspace_content_size")
    if (
        not isinstance(content_size, int)
        or isinstance(content_size, bool)
        or content_size < 0
    ):
        raise BridgeExternalMcpCommandFlowRunnerError(
            "external MCP command-flow workspace_content_size is invalid"
        )
    if result.get("workspace_content_encoding") not in {"utf-8", "base64"}:
        raise BridgeExternalMcpCommandFlowRunnerError(
            "external MCP command-flow workspace_content_encoding is invalid"
        )
    if result.get("tunnel_readiness_body_class") not in {"ready", "mcp_auth_required"}:
        raise BridgeExternalMcpCommandFlowRunnerError(
            "external MCP command-flow tunnel readiness class is invalid"
        )
    return dict(result)


def run_external_mcp_command_flow_qualification(
    *,
    challenge_path: Path,
    proof_path: Path,
    source_commit: str,
    path: str,
    expected_content_sha256: str,
    external_timeout_seconds: float = 300.0,
    environment: MutableMapping[str, str] | None = None,
) -> dict[str, object]:
    if not isinstance(challenge_path, Path) or not isinstance(proof_path, Path):
        raise TypeError("challenge_path and proof_path must be pathlib.Path")
    if challenge_path.expanduser().absolute() == proof_path.expanduser().absolute():
        raise BridgeExternalMcpCommandFlowRunnerError(
            "challenge_path and proof_path must be distinct"
        )
    require_windows_administrator()
    credential = load_bootstrap_credential_from_environment(environment)
    request = BridgeExternalMcpCommandFlowQualificationRequest(
        guest_credential=credential,
        source_commit=source_commit,
        path=path,
        expected_content_sha256=expected_content_sha256,
        challenge_path=challenge_path,
        external_timeout_seconds=external_timeout_seconds,
    )
    request.validate()
    result = validate_external_mcp_command_flow_result(
        qualify_external_mcp_read_with_stable_tunnel(request)
    )
    if (
        result["source_commit"] != source_commit
        or result["path"] != path
        or result["expected_content_sha256"] != expected_content_sha256
    ):
        raise BridgeExternalMcpCommandFlowRunnerError(
            "external MCP result differs from requested challenge authority"
        )
    proof = {
        "schema_version": _PROOF_SCHEMA_VERSION,
        "qualification": "R002F_EXTERNAL_MCP_COMMAND_FLOW_WITH_STABLE_TUNNEL",
        "status": result["status"],
        "challenge_path": str(challenge_path),
        "result": result,
    }
    write_json_create_only(
        proof_path,
        proof,
        max_bytes=_MAX_PROOF_BYTES,
        label="HMSBridge external MCP command-flow qualification proof",
    )
    return proof
