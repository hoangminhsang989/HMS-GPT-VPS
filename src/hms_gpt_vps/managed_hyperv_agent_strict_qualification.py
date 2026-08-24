from __future__ import annotations

from typing import Any

from .managed_guest_listener_probe import probe_managed_agent_health_listener_by_id
from .managed_hyperv_agent_qualification import qualify_managed_hyperv_agent
from .powershell_direct import PowerShellDirectCredential
from .provisioning import ProvisionContext
from .agent_transport_protocol import AgentDeviceCredential


class StrictManagedHyperVAgentQualificationError(RuntimeError):
    pass


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
    socket from Windows guest OS state, bound to the exact managed VMId.
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
    listener = probe_managed_agent_health_listener_by_id(
        base_proof.vm_id,
        agent_runtime.config.vm_name,
        credential,
        agent_runtime.config.service,
        agent_runtime.config.runtime.health_port,
    )
    if listener.get("os_listener_proven") is not True:
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V OS listener proof is incomplete"
        )
    if listener.get("vm_id") != base_proof.vm_id.lower():
        raise StrictManagedHyperVAgentQualificationError(
            "managed Hyper-V OS listener proof returned the wrong VMId"
        )

    payload = base_proof.to_dict()
    payload.update(
        {
            "os_listener_proven": True,
            "health_listener_process_id": listener["process_id"],
            "health_listener_count": listener["listener_count"],
            "health_listener_addresses": listener["local_addresses"],
            "health_listener_port": listener["health_port"],
        }
    )
    if payload.get("hyperv_guest_proven") is not True:
        raise StrictManagedHyperVAgentQualificationError(
            "publishable managed Hyper-V proof lost its guest verdict"
        )
    return payload
