from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .hyperv_network import HyperVNetworkConfig, ensure_internal_nat
from .hyperv_observe import HyperVObservation, observe_hyperv
from .hyperv_vm import reconcile_vm
from .install_bundle import reconcile_install_bundle
from .install_bundle_observe import InstallBundleState, observe_install_bundle
from .instance_registry import InstanceRegistry, VMRecord
from .provisioning import ProvisionObservation
from .windows_image import WindowsImage, sha256_file
from .windows_install_start import start_unattended_install
from .windows_provisioner import WindowsVMConfig


class WindowsInstallPostconditionError(RuntimeError):
    pass


@dataclass(frozen=True)
class WindowsInstallRuntimeConfig:
    instance_id: str
    vm: WindowsVMConfig
    network: HyperVNetworkConfig
    windows_image: WindowsImage
    answer_iso: Path
    answer_iso_sha256: str

    def validate(self) -> None:
        if not isinstance(self.instance_id, str) or not self.instance_id.strip():
            raise ValueError("instance_id is required")
        self.vm.validate()
        self.network.validate()
        self.windows_image.validate()
        if self.vm.switch_name != self.network.switch_name:
            raise ValueError("VM switch must match managed Hyper-V network switch")
        if self.answer_iso.suffix.lower() != ".iso":
            raise ValueError("answer media must be an ISO file")
        if not self.answer_iso.is_file():
            raise FileNotFoundError(self.answer_iso)
        if not isinstance(self.answer_iso_sha256, str) or len(self.answer_iso_sha256) != 64:
            raise ValueError("answer_iso_sha256 must contain 64 hex characters")
        try:
            int(self.answer_iso_sha256, 16)
        except ValueError as exc:
            raise ValueError("answer_iso_sha256 must be hexadecimal") from exc
        actual = sha256_file(self.answer_iso)
        if actual.lower() != self.answer_iso_sha256.lower():
            raise ValueError("answer media SHA-256 mismatch")


@dataclass(frozen=True)
class WindowsInstallObservation:
    hyperv: HyperVObservation
    bundle: InstallBundleState

    def to_provision_observation(self) -> ProvisionObservation:
        return ProvisionObservation(
            network_ready=self.hyperv.network_ready,
            vm_id=self.hyperv.vm_id,
            install_media_ready=self.bundle.ready,
            vm_running=self.hyperv.vm_running,
            guest_booted=self.hyperv.guest_heartbeat_ok,
        )


class WindowsInstallRuntime:
    """Execute R002C Tranche-3 host actions with read-after-write verification."""

    def __init__(self, config: WindowsInstallRuntimeConfig, registry_path: Path) -> None:
        config.validate()
        self.config = config
        self.registry = InstanceRegistry(registry_path)

    def _expected_vm_id(self) -> str | None:
        record = self.registry.get(self.config.instance_id)
        return record.vm_id if record is not None else None

    def _verify_answer_media(self) -> None:
        actual = sha256_file(self.config.answer_iso)
        if actual.lower() != self.config.answer_iso_sha256.lower():
            raise WindowsInstallPostconditionError("answer media changed after creation")

    def observe(self) -> WindowsInstallObservation:
        hyperv = observe_hyperv(
            self.config.vm,
            self.config.network,
            iso_path=self.config.windows_image.source,
            expected_vm_id=self._expected_vm_id(),
        )
        bundle = observe_install_bundle(
            self.config.vm,
            self.config.windows_image.source,
            self.config.answer_iso,
        )
        return WindowsInstallObservation(hyperv=hyperv, bundle=bundle)

    def provision_observation(self) -> ProvisionObservation:
        return self.observe().to_provision_observation()

    def apply(self, action: str) -> WindowsInstallObservation:
        if action == "ENSURE_INTERNAL_NAT_NETWORK":
            ensure_internal_nat(self.config.network)
            observed = self.observe()
            if not observed.hyperv.network_ready:
                raise WindowsInstallPostconditionError("Hyper-V network postcondition failed")
            return observed

        if action == "ENSURE_VM":
            result = reconcile_vm(
                self.config.vm,
                expected_vm_id=self._expected_vm_id(),
            )
            vm_id_raw = result.get("vm_id")
            if not isinstance(vm_id_raw, str) or not vm_id_raw:
                raise WindowsInstallPostconditionError("Hyper-V reconcile returned no VMId")
            vm_id = vm_id_raw
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
            if observed.hyperv.vm_id != vm_id or not observed.hyperv.vm_switch_ready:
                raise WindowsInstallPostconditionError("VM identity/network postcondition failed")
            if not observed.hyperv.windows11_security_ready:
                raise WindowsInstallPostconditionError("Secure Boot/vTPM postcondition failed")
            return observed

        if action == "ATTACH_INSTALL_MEDIA":
            self.config.windows_image.validate()
            self._verify_answer_media()
            reconcile_install_bundle(
                self.config.vm,
                self.config.windows_image.source,
                self.config.answer_iso,
            )
            observed = self.observe()
            if not observed.bundle.ready:
                raise WindowsInstallPostconditionError("install bundle postcondition failed")
            return observed

        if action == "START_UNATTENDED_INSTALL":
            self.config.windows_image.validate()
            self._verify_answer_media()
            before = self.observe()
            if not before.bundle.ready:
                raise WindowsInstallPostconditionError("install bundle is not ready")
            if not before.hyperv.windows11_security_ready:
                raise WindowsInstallPostconditionError("Windows 11 VM security is not ready")
            start_unattended_install(
                self.config.vm,
                self.config.windows_image.source,
                self.config.answer_iso,
                expected_windows_sha256=self.config.windows_image.sha256,
                expected_answer_sha256=self.config.answer_iso_sha256,
            )
            after = self.observe()
            if not after.hyperv.vm_running:
                raise WindowsInstallPostconditionError("VM start postcondition failed")
            return after

        raise NotImplementedError(f"R002C Tranche 3 does not execute action: {action}")
