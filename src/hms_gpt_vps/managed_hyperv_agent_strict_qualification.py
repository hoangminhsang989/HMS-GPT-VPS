from __future__ import annotations

from typing import Any

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


def qualify_managed_hyperv_agent_strict(
    reconcile_runtime: Any,
    context: ProvisionContext,
    credential: PowerShellDirectCredential,
    expected_device_credential: AgentDeviceCredential,
    *,
    max_reconcile_steps: int = 8,
) -> dict[str, object]:
    """Build the publishable R002E proof with independent OS listener evidence.

    ``qualify_managed_hyperv_agent`` supplies the package/SCM/health/enrollment
    evidence. This final publication gate additionally proves the real listening
    socket from Windows guest OS state, bound to the exact managed VMId. Stable
    registry/Hyper-V identity is re-proved immediately before and after that
    final OS observation so the publication boundary cannot rely on stale VM
    identity from the base qualification.
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
    listener = probe_managed_agent_health_listener_by_id(
        pre_listener_vm_id,
        agent_runtime.config.vm_name,
        credential,
        agent_runtime.config.service,
        health_port,
    )
    if listener.get("os_listener_proven") is not True:
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V OS listener proof is incomplete"
        )
    if listener.get("vm_id") != base_proof.vm_id.lower():
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V OS listener proof returned the wrong VMId"
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
            "health_listener_process_id": listener["process_id"],
            "health_listener_count": listener["listener_count"],
            "health_listener_addresses": listener["local_addresses"],
            "health_listener_port": listener["health_port"],
        }
    )
    validate_strict_managed_hyperv_proof_payload(
        payload,
        expected_health_port=health_port,
    )
    return payload
