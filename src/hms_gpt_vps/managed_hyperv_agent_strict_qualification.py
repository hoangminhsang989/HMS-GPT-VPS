from __future__ import annotations

from typing import Any

from .agent_health_contract import AgentHealthDocument
from .agent_transport_protocol import AgentDeviceCredential
from .managed_guest_listener_probe import probe_managed_agent_health_listener_by_id
from .managed_hyperv_agent_qualification import qualify_managed_hyperv_agent
from .powershell_direct import PowerShellDirectCredential
from .provisioning import ProvisionContext


STRICT_MANAGED_HYPERV_PUBLICATION_SCHEMA_VERSION = 1


class StrictManagedHyperVAgentQualificationError(RuntimeError):
    pass


def validate_strict_managed_hyperv_proof_payload(
    payload: dict[str, object],
    *,
    expected_health_port: int | None = None,
) -> None:
    if payload.get("strict_publication_schema_version") != (
        STRICT_MANAGED_HYPERV_PUBLICATION_SCHEMA_VERSION
    ):
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V publication schema mismatch"
        )
    if payload.get("hyperv_guest_proven") is not True:
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V proof did not prove the guest path"
        )
    if payload.get("os_listener_proven") is not True:
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V proof did not prove the OS listener"
        )
    for key in (
        "full_bridge_command_flow_proven",
        "bootstrap_retired",
        "pairing_ready",
    ):
        if payload.get(key) is not False:
            raise StrictManagedHyperVAgentQualificationError(
                f"strict managed Hyper-V proof crossed forbidden R002E boundary: {key}"
            )
    if payload.get("health_listener_scope") != "loopback-only":
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V health contract is not loopback-only"
        )

    process_id = payload.get("health_listener_process_id")
    if (
        not isinstance(process_id, int)
        or isinstance(process_id, bool)
        or process_id <= 0
    ):
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V listener process id is invalid"
        )
    listener_count = payload.get("health_listener_count")
    if (
        not isinstance(listener_count, int)
        or isinstance(listener_count, bool)
        or listener_count != 1
    ):
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V listener count is invalid"
        )
    addresses = payload.get("health_listener_addresses")
    if addresses != ["127.0.0.1"]:
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V listener addresses are not exclusive IPv4 loopback"
        )
    listener_port = payload.get("health_listener_port")
    if (
        not isinstance(listener_port, int)
        or isinstance(listener_port, bool)
        or listener_port < 1
        or listener_port > 65535
    ):
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V listener port is invalid"
        )
    if expected_health_port is not None and listener_port != expected_health_port:
        raise StrictManagedHyperVAgentQualificationError(
            "strict managed Hyper-V listener port differs from runtime config"
        )


def _require_fresh_observation_matches_base(
    agent_runtime: Any,
    credential: PowerShellDirectCredential,
    base_proof: Any,
) -> None:
    observation, post = agent_runtime.observe(credential)
    if not (
        observation.agent_package_ready
        and observation.agent_service_ready
        and observation.agent_healthy
    ):
        raise StrictManagedHyperVAgentQualificationError(
            "strict publication fresh Agent observation is incomplete"
        )
    if post is None or not post.service_ready or not post.agent_healthy:
        raise StrictManagedHyperVAgentQualificationError(
            "strict publication fresh post-install observation is incomplete"
        )
    health = post.health
    if not isinstance(health, AgentHealthDocument):
        raise StrictManagedHyperVAgentQualificationError(
            "strict publication fresh health document is missing"
        )
    if health.boot_id != base_proof.health_boot_id:
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V Agent service incarnation changed before publication"
        )
    if health.agent_version != base_proof.health_agent_version:
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V Agent version changed before publication"
        )

    evidence = dict(post.service_evidence)
    expected_values = {
        "package_file_count": base_proof.package_file_count,
        "package_total_size": base_proof.package_total_size,
        "binary_sha256": base_proof.package_entrypoint_sha256,
        "package_manifest_sha256": base_proof.package_manifest_sha256,
    }
    for key, expected in expected_values.items():
        actual = evidence.get(key)
        if isinstance(expected, str):
            if not isinstance(actual, str) or actual.lower() != expected.lower():
                raise StrictManagedHyperVAgentQualificationError(
                    f"strict publication fresh evidence changed: {key}"
                )
        elif actual != expected:
            raise StrictManagedHyperVAgentQualificationError(
                f"strict publication fresh evidence changed: {key}"
            )
    for key in (
        "package_tree_ok",
        "package_manifest_sha256_ok",
        "local_service_account",
        "service_sid_unrestricted",
        "runtime_config_sha256_ok",
        "service_ready",
    ):
        if evidence.get(key) is not True:
            raise StrictManagedHyperVAgentQualificationError(
                f"strict publication fresh readiness evidence is not proven: {key}"
            )


def _require_listener_matches(
    listener: dict[str, object],
    *,
    expected_vm_id: str,
) -> None:
    if listener.get("os_listener_proven") is not True:
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V OS listener proof is incomplete"
        )
    if listener.get("vm_id") != expected_vm_id.lower():
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V OS listener proof returned the wrong VMId"
        )


def qualify_managed_hyperv_agent_strict(
    reconcile_runtime: Any,
    context: ProvisionContext,
    credential: PowerShellDirectCredential,
    expected_device_credential: AgentDeviceCredential,
    *,
    max_reconcile_steps: int = 8,
) -> dict[str, object]:
    """Build the publishable R002E proof with a freshness-bound OS listener gate.

    The base qualification pins package/SCM/health/enrollment evidence. The final
    publication gate brackets one fresh full Agent observation between two
    VMId-bound guest OS listener probes and requires the same live service PID,
    VMId and health boot id throughout. This prevents publication from combining
    health/package evidence from one service incarnation with socket evidence
    from another.
    """

    base_proof = qualify_managed_hyperv_agent(
        reconcile_runtime,
        context,
        credential,
        expected_device_credential,
        max_reconcile_steps=max_reconcile_steps,
    )
    base_proof.validate()
    if not base_proof.hyperv_guest_proven:
        raise StrictManagedHyperVAgentQualificationError(
            "base managed Hyper-V qualification did not prove the guest path"
        )

    agent_runtime = reconcile_runtime.agent_runtime
    pre_listener_vm_id = agent_runtime._assert_vm_identity()
    if pre_listener_vm_id != base_proof.vm_id:
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V VMId changed before strict listener proof"
        )

    health_port = agent_runtime.config.runtime.health_port
    listener_before = probe_managed_agent_health_listener_by_id(
        pre_listener_vm_id,
        agent_runtime.config.vm_name,
        credential,
        agent_runtime.config.service,
        health_port,
    )
    _require_listener_matches(listener_before, expected_vm_id=base_proof.vm_id)

    _require_fresh_observation_matches_base(agent_runtime, credential, base_proof)

    mid_vm_id = agent_runtime._assert_vm_identity()
    if mid_vm_id != base_proof.vm_id:
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V VMId changed during strict health observation"
        )
    listener_after = probe_managed_agent_health_listener_by_id(
        mid_vm_id,
        agent_runtime.config.vm_name,
        credential,
        agent_runtime.config.service,
        health_port,
    )
    _require_listener_matches(listener_after, expected_vm_id=base_proof.vm_id)
    if listener_after.get("process_id") != listener_before.get("process_id"):
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V Agent service process changed during strict publication proof"
        )

    post_listener_vm_id = agent_runtime._assert_vm_identity()
    if post_listener_vm_id != base_proof.vm_id:
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V VMId changed during strict listener proof"
        )

    payload = base_proof.to_dict()
    payload.update(
        {
            "strict_publication_schema_version": (
                STRICT_MANAGED_HYPERV_PUBLICATION_SCHEMA_VERSION
            ),
            "os_listener_proven": True,
            "health_listener_process_id": listener_after["process_id"],
            "health_listener_count": listener_after["listener_count"],
            "health_listener_addresses": listener_after["local_addresses"],
            "health_listener_port": listener_after["health_port"],
        }
    )
    validate_strict_managed_hyperv_proof_payload(
        payload,
        expected_health_port=health_port,
    )
    return payload
