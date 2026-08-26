from __future__ import annotations

import uuid

from .bridge_activation_qualification import (
    BridgeActivationQualificationError,
    BridgeActivationQualificationRequest,
    _load_and_verify_package,
    qualify_agent_bridge_production_tls,
    start_hms_bridge_for_qualification,
    stop_hms_bridge_after_qualification,
)
from .bridge_host_deployment_transaction import derive_hms_bridge_service_sid
from .bridge_service_config_storage import load_protected_bridge_service_runtime_config
from .bridge_service_provisioning_identity import prove_hms_bridge_provisioning_identity
from .bridge_service_runtime_config import BridgeServiceRuntimeConfig
from .secure_mcp_tunnel_native_qualification import qualify_running_secure_mcp_tunnel


class BridgeCompositeActivationQualificationError(BridgeActivationQualificationError):
    pass


_TUNNEL_STABILITY_KEYS = (
    "service_process_id",
    "tunnel_process_id",
    "tunnel_parent_process_id",
    "tunnel_executable_path",
    "tunnel_executable_sha256",
    "health_attempt_path",
    "health_url_path",
    "health_base_url",
    "health_listener_host",
    "health_listener_port",
    "readiness_url",
    "readiness_status_code",
    "readiness_body_class",
)


def _require_stopped_manual_identity(
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
        raise BridgeCompositeActivationQualificationError(
            f"HMSBridge is not exact Stopped/Manual at {phase}"
        )


def _validate_managed_guest_tls(
    qualification: dict[str, object],
    *,
    runtime: object,
) -> None:
    if not isinstance(qualification, dict):
        raise BridgeCompositeActivationQualificationError(
            "managed-guest TLS qualification result type is invalid"
        )
    tls = runtime.tls
    if qualification.get("live_managed_guest_tls_proven") is not True:
        raise BridgeCompositeActivationQualificationError(
            "managed-guest TLS qualification did not pass"
        )
    if (
        qualification.get("server_certificate_sha256")
        != tls.material.certificate_der_sha256
    ):
        raise BridgeCompositeActivationQualificationError(
            "managed guest observed the wrong TLS certificate"
        )
    expected_vm_id = str(uuid.UUID(tls.guest.vm_id)).lower()
    observed_vm_id = qualification.get("vm_id")
    if not isinstance(observed_vm_id, str):
        raise BridgeCompositeActivationQualificationError(
            "managed-guest TLS proof VMId type is invalid"
        )
    try:
        canonical_observed = str(uuid.UUID(observed_vm_id)).lower()
    except (ValueError, AttributeError) as exc:
        raise BridgeCompositeActivationQualificationError(
            "managed-guest TLS proof VMId is invalid"
        ) from exc
    if canonical_observed != expected_vm_id:
        raise BridgeCompositeActivationQualificationError(
            "managed-guest TLS proof VMId differs"
        )
    if qualification.get("bridge_origin") != tls.guest.bridge_origin:
        raise BridgeCompositeActivationQualificationError(
            "managed-guest TLS proof origin differs"
        )


def _require_same_tunnel_generation(
    before: dict[str, object],
    after: dict[str, object],
) -> None:
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise BridgeCompositeActivationQualificationError(
            "native tunnel qualification result type is invalid"
        )
    if before.get("ready") is not True or after.get("ready") is not True:
        raise BridgeCompositeActivationQualificationError(
            "native tunnel qualification did not remain ready"
        )
    for key in _TUNNEL_STABILITY_KEYS:
        if before.get(key) != after.get(key):
            raise BridgeCompositeActivationQualificationError(
                f"secure MCP tunnel generation changed across managed-guest TLS probe: {key}"
            )


def qualify_hms_bridge_composite_activation_probe(
    request: BridgeActivationQualificationRequest,
) -> dict[str, object]:
    """Qualify one stopped->running->stopped generation including the tunnel child."""

    if not isinstance(request, BridgeActivationQualificationRequest):
        raise TypeError("request must be BridgeActivationQualificationRequest")
    request.validate()
    service_sid = derive_hms_bridge_service_sid()
    config = load_protected_bridge_service_runtime_config()
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise BridgeCompositeActivationQualificationError(
            "protected runtime config type is invalid"
        )
    config.validate()
    runtime = config.to_runtime_config(service_sid)
    manifest = _load_and_verify_package()

    pre = prove_hms_bridge_provisioning_identity()
    _require_stopped_manual_identity(
        pre,
        service_sid=service_sid,
        phase="composite activation start",
    )

    started = False
    start_evidence: dict[str, object] | None = None
    tunnel_before: dict[str, object] | None = None
    tunnel_after: dict[str, object] | None = None
    guest_tls: dict[str, object] | None = None
    stop_evidence: dict[str, object] | None = None
    primary_error: BaseException | None = None
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
            raise BridgeCompositeActivationQualificationError(
                "activation service process id is invalid"
            )

        tunnel_before = qualify_running_secure_mcp_tunnel(
            service_sid=service_sid,
            service_process_id=service_process_id,
        )
        guest_tls = qualify_agent_bridge_production_tls(
            runtime.tls,
            request.guest_credential,
            request.trust_root_certificate_pem,
        )
        _validate_managed_guest_tls(guest_tls, runtime=runtime)
        tunnel_after = qualify_running_secure_mcp_tunnel(
            service_sid=service_sid,
            service_process_id=service_process_id,
        )
        _require_same_tunnel_generation(tunnel_before, tunnel_after)
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
                    raise BridgeCompositeActivationQualificationError(
                        "composite qualification failed and HMSBridge stop also failed"
                    ) from stop_exc

    if primary_error is not None:
        raise primary_error
    if (
        start_evidence is None
        or tunnel_before is None
        or tunnel_after is None
        or guest_tls is None
        or stop_evidence is None
    ):
        raise BridgeCompositeActivationQualificationError(
            "composite activation qualification evidence is incomplete"
        )

    post = prove_hms_bridge_provisioning_identity()
    _require_stopped_manual_identity(
        post,
        service_sid=service_sid,
        phase="composite activation end",
    )

    return {
        "ready": True,
        "status": "QUALIFIED_STOPPED",
        "service_sid": service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "service_runtime_ready_proven": True,
        "tls_listener_ready_during_probe": True,
        "mcp_listener_ready_during_probe": True,
        "secure_mcp_tunnel_ready_during_probe": True,
        "runtime_process_id": start_evidence["process_id"],
        "tunnel_process_id": tunnel_after["tunnel_process_id"],
        "tunnel_executable_sha256": tunnel_after["tunnel_executable_sha256"],
        "tunnel_readiness_body_class": tunnel_after["readiness_body_class"],
        "tunnel_stable_across_managed_guest_probe": True,
        "live_managed_guest_tls_proven": True,
        "server_certificate_sha256": guest_tls["server_certificate_sha256"],
        "vm_id": guest_tls["vm_id"],
        "bridge_origin": guest_tls["bridge_origin"],
        "listeners_absent_after_stop": True,
        "authenticated_agent_transport_proven": False,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
