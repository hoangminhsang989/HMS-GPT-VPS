from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .hyperv_network import HyperVNetworkConfig, ensure_internal_nat
from .hyperv_observe import HyperVObservation, observe_hyperv
from .hyperv_vm import reconcile_vm
from .install_media import attach_windows_iso
from .instance_registry import InstanceRegistry, VMRecord
from .provisioning import ProvisionObservation
from .windows_image import WindowsImage
from .windows_provisioner import WindowsVMConfig


class ProvisionPostconditionError(RuntimeError):
    pass


@dataclass(frozen=True)
class HyperVRuntimeConfig:
    instance_id: str
    vm: WindowsVMConfig
    network: HyperVNetworkConfig
    image: WindowsImage

    def validate(self) -> None:
        if not self.instance_id.strip():
            raise ValueError("instance_id is required")
        self.vm.validate()
        self.network.validate()
        self.image.validate()
        if self.vm.switch_name != self.network.switch_name:
            raise ValueError("VM switch must match managed Hyper-V network switch")


class HyperVTranche2Runtime:
    """Execute R002C host mutations with read-after-write verification.

    This runtime intentionally supports only Tranche-2 actions. Starting Windows
    Setup and all guest bootstrap work stay blocked until Tranche 3 provides the
    unattended-install artifact pipeline.
    """

    def __init__(self, config: HyperVRuntimeConfig, registry_path: Path) -> None:
        config.validate()
        self.config = config
        self.registry = InstanceRegistry(registry_path)

    def _expected_vm_id(self) -> str | None:
        record = self.registry.get(self.config.instance_id)
        return record.vm_id if record is not None else None

    def observe(self) -> HyperVObservation:
        return observe_hyperv(
            self.config.vm,
            self.config.network,
            iso_path=self.config.image.source,
            expected_vm_id=self._expected_vm_id(),
        )

    def provision_observation(self) -> ProvisionObservation:
        observed = self.observe()
        return ProvisionObservation(
            network_ready=observed.network_ready,
            vm_id=observed.vm_id,
            install_media_ready=observed.install_media_ready,
            vm_running=observed.vm_running,
            guest_booted=observed.guest_heartbeat_ok,
        )

    def apply(self, action: str) -> HyperVObservation:
        if action == "ENSURE_INTERNAL_NAT_NETWORK":
            ensure_internal_nat(self.config.network)
            observed = self.observe()
            if not observed.network_ready:
                raise ProvisionPostconditionError("Hyper-V network postcondition failed")
            return observed

        if action == "ENSURE_VM":
            result = reconcile_vm(
                self.config.vm,
                expected_vm_id=self._expected_vm_id(),
            )
            vm_id_raw = result.get("vm_id")
            if not vm_id_raw:
                raise ProvisionPostconditionError("Hyper-V reconcile returned no VMId")
            vm_id = str(vm_id_raw)
            self.registry.upsert(
                VMRecord(
                    instance_id=self.config.instance_id,
                    vm_name=self.config.vm.name,
                    backend="hyperv",
                    phase="vm_created",
                    workspace_path=self.config.vm.workspace_path,
                    vm_id=vm_id,
                    switch_name=self.config.network.switch_name,
                    guest_ipv4=self.config.network.guest_ipv4,
                )
            )
            observed = self.observe()
            if observed.vm_id != vm_id or not observed.vm_switch_ready:
                raise ProvisionPostconditionError("Hyper-V VM identity/network postcondition failed")
            return observed

        if action == "ATTACH_INSTALL_MEDIA":
            self.config.image.validate()
            attach_windows_iso(self.config.vm, self.config.image.source)
            observed = self.observe()
            if not observed.install_media_ready:
                raise ProvisionPostconditionError("Windows ISO attachment postcondition failed")
            return observed

        raise NotImplementedError(f"R002C Tranche 2 does not execute action: {action}")
