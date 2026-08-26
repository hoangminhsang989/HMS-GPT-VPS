from __future__ import annotations

from pathlib import Path
from typing import MutableMapping

from .bridge_external_mcp_command_flow_qualification import (
    BridgeExternalMcpCommandFlowQualificationRequest,
)
from .bridge_external_mcp_command_flow_runner import (
    BridgeExternalMcpCommandFlowRunnerError,
    load_bootstrap_credential_from_environment,
    require_windows_administrator,
)
from .bridge_openai_control_plane_command_flow_qualification import (
    qualify_openai_control_plane_mcp_read,
)
from .external_mcp_command_flow_contract import (
    canonical_git_sha1,
    canonical_sha256,
    identifier,
    qualification_path,
)
from .openai_control_plane_origin_authority import (
    OPENAI_TUNNEL_ORIGIN_KIND,
    current_openai_control_plane_static_authority,
)
from .qualification_file_authority import write_json_create_only

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
        "mcp_ingress_generation",
        "launch_command_line_sha256",
        "openai_origin_kind",
        "openai_tunnel_upstream_commit",
        "openai_tunnel_upstream_tree",
        "openai_tunnel_release_asset_sha256",
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
        "mcp_adapter_invocation_proven",
        "secure_tunnel_generation_proven",
        "openai_tunnel_launch_profile_proven",
        "openai_control_plane_origin_proven",
        "chatgpt_ui_origin_proven",
        "full_bridge_command_flow_proven",
        "listeners_absent_after_stop",
        "bootstrap_retired",
        "pairing_ready",
        "automatic_start_enabled",
    }
)


class BridgeOpenAiControlPlaneCommandFlowRunnerError(
    BridgeExternalMcpCommandFlowRunnerError
):
    pass


def validate_openai_control_plane_command_flow_result(
    result: dict[str, object],
) -> dict[str, object]:
    if not isinstance(result, dict) or frozenset(result) != _RESULT_KEYS:
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow result schema is invalid"
        )
    for key in (
        "ready",
        "authenticated_principal_control_path_proven",
        "durable_external_principal_read_proven",
        "mcp_adapter_invocation_proven",
        "secure_tunnel_generation_proven",
        "openai_tunnel_launch_profile_proven",
        "openai_control_plane_origin_proven",
        "listeners_absent_after_stop",
    ):
        if result.get(key) is not True:
            raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
                f"OpenAI control-plane command-flow did not prove {key}"
            )
    for key in (
        "runner_invoked_mcp",
        "runner_enqueued_agent_command",
        "chatgpt_ui_origin_proven",
        "full_bridge_command_flow_proven",
        "bootstrap_retired",
        "pairing_ready",
        "automatic_start_enabled",
    ):
        if result.get(key) is not False:
            raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
                f"OpenAI control-plane command-flow escaped staged proof boundary: {key}"
            )
    if result.get("status") != "OPENAI_CONTROL_PLANE_PRINCIPAL_READ_QUALIFIED_STOPPED":
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow status is invalid"
        )
    if result.get("service_state") != "Stopped" or result.get("service_start_mode") != "Manual":
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow did not return HMSBridge to Stopped/Manual"
        )
    for key in (
        "runtime_process_id",
        "tunnel_process_id",
        "session_epoch",
    ):
        value = result.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
                f"OpenAI control-plane command-flow has invalid {key}"
            )
    try:
        canonical_git_sha1(result.get("source_commit"))
        qualification_path(result.get("path"))
        for key in (
            "expected_content_sha256",
            "tunnel_executable_sha256",
            "launch_command_line_sha256",
            "openai_tunnel_release_asset_sha256",
            "principal_sha256",
            "agent_result_sha256",
        ):
            canonical_sha256(result.get(key), key)
        for key in (
            "challenge_id",
            "instance_id",
            "request_id",
            "pair_id",
            "session_id",
        ):
            identifier(result.get(key), key)
    except Exception as exc:
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow identity/digest authority is invalid"
        ) from exc
    generation = result.get("mcp_ingress_generation")
    if (
        not isinstance(generation, str)
        or len(generation) != 32
        or generation != generation.lower()
        or any(char not in "0123456789abcdef" for char in generation)
    ):
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow ingress generation is invalid"
        )
    content_size = result.get("workspace_content_size")
    if (
        not isinstance(content_size, int)
        or isinstance(content_size, bool)
        or content_size < 0
    ):
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow workspace_content_size is invalid"
        )
    if result.get("workspace_content_encoding") not in {"utf-8", "base64"}:
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow workspace_content_encoding is invalid"
        )
    if result.get("tunnel_readiness_body_class") not in {"ready", "mcp_auth_required"}:
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow tunnel readiness class is invalid"
        )
    authority = current_openai_control_plane_static_authority()
    if (
        result.get("openai_origin_kind") != OPENAI_TUNNEL_ORIGIN_KIND
        or result.get("openai_tunnel_upstream_commit") != authority.upstream_commit_sha
        or result.get("openai_tunnel_upstream_tree") != authority.upstream_tree_sha
        or result.get("openai_tunnel_release_asset_sha256") != authority.release_asset_sha256
    ):
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane command-flow upstream authority differs"
        )
    return dict(result)


def run_openai_control_plane_command_flow_qualification(
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
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
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
    result = validate_openai_control_plane_command_flow_result(
        qualify_openai_control_plane_mcp_read(request)
    )
    if (
        result["source_commit"] != source_commit
        or result["path"] != path
        or result["expected_content_sha256"] != expected_content_sha256
    ):
        raise BridgeOpenAiControlPlaneCommandFlowRunnerError(
            "OpenAI control-plane result differs from requested challenge authority"
        )
    proof = {
        "schema_version": _PROOF_SCHEMA_VERSION,
        "qualification": "R002F_OPENAI_CONTROL_PLANE_COMMAND_FLOW",
        "status": result["status"],
        "challenge_path": str(challenge_path),
        "result": result,
    }
    write_json_create_only(
        proof_path,
        proof,
        max_bytes=_MAX_PROOF_BYTES,
        label="HMSBridge OpenAI control-plane command-flow qualification proof",
    )
    return proof
