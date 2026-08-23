from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .provision_state import ProvisionRecord, ProvisionState, ProvisionStateStore
from .windows_image import WindowsImage
from .windows_provisioner import HyperVHostState, WindowsVMConfig


@dataclass(frozen=True)
class ProvisionContext:
    instance_id: str
    config: WindowsVMConfig
    host: HyperVHostState
    image: WindowsImage | None


@dataclass(frozen=True)
class TransitionResult:
    record: ProvisionRecord
    action: str
    requires_operator_approval: bool = False
    requires_reboot: bool = False


class ProvisioningOrchestrator:
    """Persistent reconcile-oriented R002C provisioning state machine.

    This class decides the next safe state. Host mutation remains delegated to
    the dedicated Hyper-V/elevation/image/bootstrap modules.
    """

    def __init__(self, state_path: Path) -> None:
        self.store = ProvisionStateStore(state_path)

    def current(self, instance_id: str) -> ProvisionRecord:
        record = self.store.load()
        if record is None:
            return self.store.transition(instance_id=instance_id, state=ProvisionState.IDLE)
        if record.instance_id != instance_id:
            raise ValueError("state file belongs to another instance")
        return record

    def reconcile(self, context: ProvisionContext) -> TransitionResult:
        record = self.current(context.instance_id)

        if record.state in {ProvisionState.READY, ProvisionState.FAILED}:
            return TransitionResult(record=record, action="NOOP")

        if record.state is ProvisionState.IDLE:
            next_record = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.PREFLIGHT,
                increment_attempt=True,
            )
            return TransitionResult(next_record, "RUN_PREFLIGHT")

        if record.state is ProvisionState.PREFLIGHT:
            if not context.host.is_windows:
                failed = self.store.transition(
                    instance_id=context.instance_id,
                    state=ProvisionState.FAILED,
                    last_error="Windows host required",
                )
                return TransitionResult(failed, "BLOCK_UNSUPPORTED_HOST")
            if not context.host.virtualization_firmware_enabled or not context.host.hyperv_available:
                failed = self.store.transition(
                    instance_id=context.instance_id,
                    state=ProvisionState.FAILED,
                    last_error="Hyper-V or firmware virtualization unavailable",
                )
                return TransitionResult(failed, "BLOCK_HYPERV_UNAVAILABLE")
            if not context.host.hyperv_enabled:
                pending = self.store.transition(
                    instance_id=context.instance_id,
                    state=ProvisionState.NEED_ELEVATION,
                    reason="enable_hyperv",
                    resume_state=ProvisionState.PREFLIGHT,
                )
                return TransitionResult(
                    pending,
                    "REQUEST_HYPERV_ENABLE_APPROVAL",
                    requires_operator_approval=True,
                )
            if context.host.restart_required:
                pending = self.store.transition(
                    instance_id=context.instance_id,
                    state=ProvisionState.REBOOT_PENDING,
                    reason="hyperv_restart_required",
                    resume_state=ProvisionState.PREFLIGHT,
                )
                return TransitionResult(pending, "REQUEST_REBOOT", requires_reboot=True)
            ready = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.IMAGE_READY if context.image else ProvisionState.PREFLIGHT,
                reason=None if context.image else "windows_image_required",
            )
            action = "VERIFY_IMAGE" if context.image else "WAIT_FOR_WINDOWS_IMAGE"
            return TransitionResult(ready, action)

        if record.state is ProvisionState.NEED_ELEVATION:
            return TransitionResult(
                record,
                "WAIT_FOR_OPERATOR_APPROVAL",
                requires_operator_approval=True,
            )

        if record.state is ProvisionState.REBOOT_PENDING:
            return TransitionResult(record, "WAIT_FOR_REBOOT", requires_reboot=True)

        if record.state is ProvisionState.IMAGE_READY:
            next_record = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.NETWORK_READY,
            )
            return TransitionResult(next_record, "ENSURE_INTERNAL_NAT_NETWORK")

        if record.state is ProvisionState.NETWORK_READY:
            next_record = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.VM_CREATED,
            )
            return TransitionResult(next_record, "ENSURE_VM")

        if record.state is ProvisionState.VM_CREATED:
            next_record = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.INSTALL_MEDIA_READY,
            )
            return TransitionResult(next_record, "ATTACH_INSTALL_MEDIA")

        if record.state is ProvisionState.INSTALL_MEDIA_READY:
            next_record = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.OS_INSTALLING,
            )
            return TransitionResult(next_record, "START_UNATTENDED_INSTALL")

        if record.state is ProvisionState.OS_INSTALLING:
            return TransitionResult(record, "WAIT_FOR_GUEST_HEARTBEAT")

        if record.state is ProvisionState.GUEST_BOOTED:
            next_record = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.GUEST_BOOTSTRAP,
            )
            return TransitionResult(next_record, "BOOTSTRAP_GUEST_WITH_POWERSHELL_DIRECT")

        if record.state is ProvisionState.GUEST_BOOTSTRAP:
            next_record = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.AGENT_INSTALLING,
            )
            return TransitionResult(next_record, "INSTALL_HMS_AGENT")

        if record.state is ProvisionState.AGENT_INSTALLING:
            return TransitionResult(record, "WAIT_FOR_AGENT_HEALTH")

        if record.state is ProvisionState.AGENT_HEALTHY:
            next_record = self.store.transition(
                instance_id=context.instance_id,
                state=ProvisionState.PAIRING_PENDING,
            )
            return TransitionResult(next_record, "CREATE_ONE_TIME_PAIRING")

        if record.state is ProvisionState.PAIRING_PENDING:
            return TransitionResult(record, "WAIT_FOR_PAIRING")

        return TransitionResult(record, "RECONCILE_EXTERNAL_SIGNAL")

    def mark_guest_booted(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition(instance_id=instance_id, state=ProvisionState.GUEST_BOOTED)

    def mark_agent_healthy(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition(instance_id=instance_id, state=ProvisionState.AGENT_HEALTHY)

    def mark_ready(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition(instance_id=instance_id, state=ProvisionState.READY)
