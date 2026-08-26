from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .bridge_external_mcp_command_flow_qualification import (
    BridgeExternalMcpCommandFlowQualificationError,
    BridgeExternalMcpCommandFlowQualificationRequest,
    BridgeServiceRuntimeConfig,
    ExternalMcpReadChallenge,
    _MAX_CHALLENGE_FILE_BYTES,
    _challenge_payload,
    _load_and_verify_package,
    _new_challenge,
    _observe_guest_agent,
    _read_presence_read_only,
    _require_same_tunnel_generation,
    _require_stopped_manual,
    _wait_for_authenticated_hello,
    _wait_for_external_observation,
    _wait_for_heartbeat_generation_stability,
    derive_hms_bridge_service_sid,
    load_protected_bridge_service_runtime_config,
    prove_hms_bridge_provisioning_identity,
    start_hms_bridge_for_qualification,
    stop_hms_bridge_after_qualification,
    write_json_create_only,
)
from .secure_mcp_tunnel_ingress_generation_qualification import (
    qualify_running_secure_mcp_tunnel_with_ingress_generation,
)

def _require_observer_success(
    evidence: dict[str, object],
    challenge: ExternalMcpReadChallenge,
) -> None:
    if not isinstance(evidence, dict):
        raise BridgeExternalMcpCommandFlowQualificationError(
            "external MCP observer returned invalid evidence"
        )
    challenge.validate()
    expected_identity = {
        "challenge_id": challenge.challenge_id,
        "source_commit": challenge.source_commit,
        "instance_id": challenge.instance_id,
        "request_id": challenge.request_id,
        "path": challenge.path,
        "expected_content_sha256": challenge.expected_content_sha256,
    }
    for key, wanted in expected_identity.items():
        if evidence.get(key) != wanted:
            raise BridgeExternalMcpCommandFlowQualificationError(
                f"external MCP observer identity differs: {key}"
            )
    for key in (
        "ready",
        "pairing_record_consumed",
        "principal_binding_proven",
        "control_session_proven",
        "dispatch_intent_proven",
        "idempotency_completion_receipt_proven",
        "agent_command_result_proven",
        "authenticated_principal_control_path_proven",
        "mcp_ingress_provenance_present",
        "mcp_adapter_invocation_proven",
    ):
        if evidence.get(key) is not True:
            raise BridgeExternalMcpCommandFlowQualificationError(
                f"external MCP observer did not prove {key}"
            )
    generation = evidence.get("mcp_ingress_generation")
    if (
        not isinstance(generation, str)
        or len(generation) != 32
        or generation != generation.lower()
        or any(char not in "0123456789abcdef" for char in generation)
    ):
        raise BridgeExternalMcpCommandFlowQualificationError(
            "external MCP observer ingress generation is noncanonical"
        )
    for key in (
        "openai_control_plane_origin_proven",
        "secure_tunnel_generation_proven",
        "full_bridge_command_flow_proven",
    ):
        if evidence.get(key) is not False:
            raise BridgeExternalMcpCommandFlowQualificationError(
                f"external MCP observer escaped its proof boundary: {key}"
            )


def qualify_external_mcp_read_with_stable_tunnel(
    request: BridgeExternalMcpCommandFlowQualificationRequest,
) -> dict[str, object]:
    """Bracket one externally-issued principal read with one live tunnel/Agent generation.

    The runner publishes only a non-secret challenge. It never invokes MCP, never
    constructs a principal, and never enqueues an Agent command. A successful run
    therefore proves an externally coordinated durable principal read occurred
    while one reviewed HMSBridge/tunnel/Agent generation stayed stable. It does
    not by itself prove the initiating caller was the OpenAI control plane.
    """

    if not isinstance(request, BridgeExternalMcpCommandFlowQualificationRequest):
        raise TypeError(
            "request must be BridgeExternalMcpCommandFlowQualificationRequest"
        )
    request.validate()
    service_sid = derive_hms_bridge_service_sid()
    config = load_protected_bridge_service_runtime_config()
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise BridgeExternalMcpCommandFlowQualificationError(
            "protected Bridge runtime config type is invalid"
        )
    config.validate()
    config.to_runtime_config(service_sid)
    manifest = _load_and_verify_package()
    pre = prove_hms_bridge_provisioning_identity()
    _require_stopped_manual(
        pre,
        service_sid=service_sid,
        phase="external MCP qualification start",
    )

    guest_before = _observe_guest_agent(config, request.guest_credential)
    presence_path = Path(config.runtime_root) / "db" / "agent-presence.sqlite3"
    started_at_unix = datetime.now(timezone.utc).timestamp()
    started = False
    primary_error: BaseException | None = None
    start_evidence: dict[str, object] | None = None
    stop_evidence: dict[str, object] | None = None
    tunnel_before: dict[str, object] | None = None
    tunnel_after: dict[str, object] | None = None
    observer: dict[str, object] | None = None
    challenge: ExternalMcpReadChallenge | None = None
    hello = None
    heartbeat = None
    try:
        start_evidence = start_hms_bridge_for_qualification(
            config,
            manifest,
            service_sid,
        )
        started = True
        service_process_id = start_evidence.get("process_id")
        if (
            not isinstance(service_process_id, int)
            or isinstance(service_process_id, bool)
            or service_process_id <= 0
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "activation service process id is invalid"
            )
        tunnel_before = qualify_running_secure_mcp_tunnel_with_ingress_generation(
            service_sid=service_sid,
            service_process_id=service_process_id,
        )
        hello = _wait_for_authenticated_hello(
            presence_path,
            instance_id=config.instance_id,
            boot_id=str(guest_before["health_boot_id"]),
            not_before_unix=started_at_unix,
            timeout_seconds=float(request.hello_timeout_seconds),
        )
        heartbeat = _wait_for_heartbeat_generation_stability(
            presence_path,
            hello,
            margin_seconds=float(request.heartbeat_margin_seconds),
        )
        guest_after_heartbeat = _observe_guest_agent(
            config,
            request.guest_credential,
        )
        if (
            guest_after_heartbeat["health_boot_id"] != hello.boot_id
            or guest_after_heartbeat["process_id"] != guest_before["process_id"]
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "HMSAgent process/boot changed before external challenge publication"
            )

        challenge = _new_challenge(request, instance_id=config.instance_id)
        write_json_create_only(
            request.challenge_path,
            _challenge_payload(challenge),
            max_bytes=_MAX_CHALLENGE_FILE_BYTES,
            label="external MCP read qualification challenge",
        )
        observer = _wait_for_external_observation(
            Path(config.runtime_root),
            challenge,
            timeout_seconds=float(request.external_timeout_seconds),
        )
        _require_observer_success(observer, challenge)
        ingress_generation = observer["mcp_ingress_generation"]
        if tunnel_before.get("mcp_ingress_generation") != ingress_generation:
            raise BridgeExternalMcpCommandFlowQualificationError(
                "protected MCP request provenance differs from native tunnel generation"
            )

        after_result = _read_presence_read_only(
            presence_path,
            config.instance_id,
        )
        if (
            after_result is None
            or after_result.device_id != hello.device_id
            or after_result.boot_id != hello.boot_id
            or after_result.connection_epoch != hello.connection_epoch
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "Agent generation changed across external MCP read"
            )
        guest_after_result = _observe_guest_agent(
            config,
            request.guest_credential,
        )
        if (
            guest_after_result["health_boot_id"] != hello.boot_id
            or guest_after_result["process_id"] != guest_before["process_id"]
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "HMSAgent process/boot changed across external MCP read"
            )
        tunnel_after = qualify_running_secure_mcp_tunnel_with_ingress_generation(
            service_sid=service_sid,
            service_process_id=service_process_id,
        )
        try:
            _require_same_tunnel_generation(tunnel_before, tunnel_after)
        except Exception as exc:
            raise BridgeExternalMcpCommandFlowQualificationError(
                "secure MCP tunnel generation changed across external MCP read"
            ) from exc
        if (
            tunnel_after.get("mcp_ingress_generation") != ingress_generation
            or tunnel_before.get("mcp_ingress_generation")
            != tunnel_after.get("mcp_ingress_generation")
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "protected MCP request provenance is not bound to one native tunnel generation"
            )
    except BaseException as exc:
        primary_error = exc
    finally:
        if started:
            try:
                stop_evidence = stop_hms_bridge_after_qualification(
                    config,
                    service_sid,
                )
            except BaseException as stop_exc:
                if primary_error is None:
                    primary_error = stop_exc
                else:
                    raise BridgeExternalMcpCommandFlowQualificationError(
                        "external MCP qualification failed and HMSBridge stop also failed"
                    ) from stop_exc

    if primary_error is not None:
        raise primary_error
    if any(
        value is None
        for value in (
            start_evidence,
            stop_evidence,
            tunnel_before,
            tunnel_after,
            observer,
            challenge,
            hello,
            heartbeat,
        )
    ):
        raise BridgeExternalMcpCommandFlowQualificationError(
            "external MCP qualification evidence is incomplete"
        )
    post = prove_hms_bridge_provisioning_identity()
    _require_stopped_manual(
        post,
        service_sid=service_sid,
        phase="external MCP qualification end",
    )

    return {
        "ready": True,
        "status": "EXTERNAL_PRINCIPAL_READ_WITH_STABLE_TUNNEL_QUALIFIED_STOPPED",
        "service_sid": service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "runtime_process_id": start_evidence["process_id"],
        "tunnel_process_id": tunnel_after["tunnel_process_id"],
        "tunnel_executable_sha256": tunnel_after["tunnel_executable_sha256"],
        "tunnel_readiness_body_class": tunnel_after["readiness_body_class"],
        "secure_mcp_tunnel_ready_during_external_flow": True,
        "tunnel_stable_across_external_flow": True,
        "agent_process_id": guest_before["process_id"],
        "agent_device_id": hello.device_id,
        "agent_boot_id": hello.boot_id,
        "agent_connection_epoch": hello.connection_epoch,
        "agent_generation_stable_across_external_flow": True,
        "challenge_id": challenge.challenge_id,
        "source_commit": challenge.source_commit,
        "instance_id": challenge.instance_id,
        "request_id": challenge.request_id,
        "path": challenge.path,
        "expected_content_sha256": challenge.expected_content_sha256,
        "workspace_content_size": observer["workspace_content_size"],
        "workspace_content_encoding": observer["workspace_content_encoding"],
        "principal_sha256": observer["principal_sha256"],
        "pair_id": observer["pair_id"],
        "session_id": observer["session_id"],
        "session_epoch": observer["session_epoch"],
        "agent_result_sha256": observer["agent_result_sha256"],
        "mcp_ingress_generation": observer["mcp_ingress_generation"],
        "authenticated_principal_control_path_proven": True,
        "durable_external_principal_read_proven": True,
        "runner_invoked_mcp": False,
        "runner_enqueued_agent_command": False,
        "secure_tunnel_generation_proven": True,
        "listeners_absent_after_stop": True,
        "mcp_adapter_invocation_proven": True,
        "openai_control_plane_origin_proven": False,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
