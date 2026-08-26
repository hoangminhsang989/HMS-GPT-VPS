from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .bridge_agent_transport_qualification import (
    BridgeAgentTransportQualificationError,
    BridgeAgentTransportQualificationRequest,
    _QUALIFICATION_ACTION,
    _enqueue_read_only_git_status,
    _load_and_verify_package,
    _observe_guest_agent,
    _read_presence_read_only,
    _wait_for_authenticated_hello,
    _wait_for_heartbeat_generation_stability,
    _wait_for_result,
    start_hms_bridge_for_qualification,
    stop_hms_bridge_after_qualification,
)
from .bridge_composite_activation_qualification import _require_same_tunnel_generation
from .bridge_host_deployment_transaction import derive_hms_bridge_service_sid
from .bridge_service_config_storage import load_protected_bridge_service_runtime_config
from .bridge_service_provisioning_identity import prove_hms_bridge_provisioning_identity
from .bridge_service_runtime_config import BridgeServiceRuntimeConfig
from .secure_mcp_tunnel_native_qualification import qualify_running_secure_mcp_tunnel


class BridgeCompositeAgentTransportQualificationError(
    BridgeAgentTransportQualificationError
):
    pass


def _require_stopped_manual(
    evidence: dict[str, object],
    *,
    service_sid: str,
    phase: str,
) -> None:
    if (
        not isinstance(evidence, dict)
        or evidence.get("service_sid") != service_sid
        or evidence.get("service_state") != "Stopped"
        or evidence.get("service_start_mode") != "Manual"
    ):
        raise BridgeCompositeAgentTransportQualificationError(
            f"HMSBridge is not exact Stopped/Manual at {phase}"
        )


def qualify_authenticated_agent_transport_with_secure_tunnel(
    request: BridgeAgentTransportQualificationRequest,
) -> dict[str, object]:
    """Prove one authenticated Agent transport generation with one stable tunnel child."""

    if not isinstance(request, BridgeAgentTransportQualificationRequest):
        raise TypeError("request must be BridgeAgentTransportQualificationRequest")
    request.validate()
    service_sid = derive_hms_bridge_service_sid()
    config = load_protected_bridge_service_runtime_config()
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise BridgeCompositeAgentTransportQualificationError(
            "protected Bridge runtime config type is invalid"
        )
    config.validate()
    config.to_runtime_config(service_sid)
    manifest = _load_and_verify_package()
    pre = prove_hms_bridge_provisioning_identity()
    _require_stopped_manual(
        pre,
        service_sid=service_sid,
        phase="composite transport start",
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
    hello = None
    heartbeat = None
    result = None
    request_id: str | None = None
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
            raise BridgeCompositeAgentTransportQualificationError(
                "activation service process id is invalid"
            )
        tunnel_before = qualify_running_secure_mcp_tunnel(
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
            raise BridgeCompositeAgentTransportQualificationError(
                "HMSAgent process/boot changed across heartbeat qualification"
            )
        store, request_id = _enqueue_read_only_git_status(
            config,
            service_sid=service_sid,
            expected_device_id=hello.device_id,
        )
        result = _wait_for_result(
            store,
            instance_id=config.instance_id,
            request_id=request_id,
            timeout_seconds=float(request.command_timeout_seconds),
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
            raise BridgeCompositeAgentTransportQualificationError(
                "Agent generation changed across poll/result qualification"
            )
        guest_after_result = _observe_guest_agent(
            config,
            request.guest_credential,
        )
        if (
            guest_after_result["health_boot_id"] != hello.boot_id
            or guest_after_result["process_id"] != guest_before["process_id"]
        ):
            raise BridgeCompositeAgentTransportQualificationError(
                "HMSAgent process/boot changed across result qualification"
            )
        tunnel_after = qualify_running_secure_mcp_tunnel(
            service_sid=service_sid,
            service_process_id=service_process_id,
        )
        try:
            _require_same_tunnel_generation(tunnel_before, tunnel_after)
        except Exception as exc:
            raise BridgeCompositeAgentTransportQualificationError(
                "secure MCP tunnel generation changed across authenticated Agent transport"
            ) from exc
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
                    raise BridgeCompositeAgentTransportQualificationError(
                        "composite transport qualification failed and HMSBridge stop also failed"
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
            hello,
            heartbeat,
            result,
            request_id,
        )
    ):
        raise BridgeCompositeAgentTransportQualificationError(
            "composite authenticated transport evidence is incomplete"
        )
    post = prove_hms_bridge_provisioning_identity()
    _require_stopped_manual(
        post,
        service_sid=service_sid,
        phase="composite transport end",
    )

    return {
        "ready": True,
        "status": "AUTHENTICATED_AGENT_TRANSPORT_WITH_TUNNEL_QUALIFIED_STOPPED",
        "service_sid": service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "runtime_process_id": start_evidence["process_id"],
        "tunnel_process_id": tunnel_after["tunnel_process_id"],
        "tunnel_executable_sha256": tunnel_after["tunnel_executable_sha256"],
        "tunnel_readiness_body_class": tunnel_after["readiness_body_class"],
        "secure_mcp_tunnel_ready_during_transport": True,
        "tunnel_stable_across_authenticated_transport": True,
        "agent_process_id": guest_before["process_id"],
        "agent_device_id": hello.device_id,
        "agent_boot_id": hello.boot_id,
        "agent_connection_epoch": hello.connection_epoch,
        "authenticated_hello_proven": True,
        "authenticated_heartbeat_proven": True,
        "authenticated_poll_proven": True,
        "authenticated_result_proven": True,
        "authenticated_agent_transport_proven": True,
        "qualification_action": _QUALIFICATION_ACTION,
        "qualification_request_id": request_id,
        "qualification_result_outcome": result.outcome,
        "listeners_absent_after_stop": True,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
