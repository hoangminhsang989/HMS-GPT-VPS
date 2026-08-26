from __future__ import annotations

from pathlib import PureWindowsPath

from .mcp_tunnel_ingress import MCP_TUNNEL_INGRESS_GENERATION_HEX_LENGTH
from .secure_mcp_tunnel_native_qualification import qualify_running_secure_mcp_tunnel


class SecureMcpTunnelIngressGenerationQualificationError(RuntimeError):
    pass


def _canonical_generation(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != MCP_TUNNEL_INGRESS_GENERATION_HEX_LENGTH
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise SecureMcpTunnelIngressGenerationQualificationError(
            "native tunnel ingress generation is noncanonical"
        )
    return value


def extract_mcp_ingress_generation_from_native_evidence(
    evidence: dict[str, object],
) -> str:
    if not isinstance(evidence, dict) or evidence.get("ready") is not True:
        raise SecureMcpTunnelIngressGenerationQualificationError(
            "native tunnel evidence is not ready"
        )
    attempt_path = evidence.get("health_attempt_path")
    health_url_path = evidence.get("health_url_path")
    if not isinstance(attempt_path, str) or not isinstance(health_url_path, str):
        raise SecureMcpTunnelIngressGenerationQualificationError(
            "native tunnel health authority is unavailable"
        )
    attempt = PureWindowsPath(attempt_path)
    if not attempt.name.startswith("attempt-"):
        raise SecureMcpTunnelIngressGenerationQualificationError(
            "native tunnel health attempt lacks canonical prefix"
        )
    generation = _canonical_generation(attempt.name.removeprefix("attempt-"))
    if PureWindowsPath(health_url_path) != attempt / "health-url.txt":
        raise SecureMcpTunnelIngressGenerationQualificationError(
            "native tunnel health URL file differs from ingress generation attempt"
        )
    return generation


def qualify_running_secure_mcp_tunnel_with_ingress_generation(
    *,
    service_sid: str,
    service_process_id: int,
) -> dict[str, object]:
    evidence = qualify_running_secure_mcp_tunnel(
        service_sid=service_sid,
        service_process_id=service_process_id,
    )
    generation = extract_mcp_ingress_generation_from_native_evidence(evidence)
    if "mcp_ingress_generation" in evidence:
        raise SecureMcpTunnelIngressGenerationQualificationError(
            "base native evidence unexpectedly already contains ingress generation"
        )
    result = dict(evidence)
    result["mcp_ingress_generation"] = generation
    return result
