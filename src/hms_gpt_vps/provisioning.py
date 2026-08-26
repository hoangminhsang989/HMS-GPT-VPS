from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import uuid

from .provision_state import ProvisionRecord, ProvisionState, ProvisionStateStore
from .windows_image import WindowsImage
from .windows_provisioner import HyperVHostState, WindowsVMConfig


@dataclass(frozen=True)
class ProvisionObservation:
    network_ready: bool = False
    vm_id: str | None = None
    install_media_ready: bool = False
    vm_running: bool = False
    guest_booted: bool = False
    guest_bootstrap_ready: bool = False
    agent_device_enrolled: bool = False
    agent_package_ready: bool = False
    agent_service_ready: bool = False
    agent_healthy: bool = False
    bootstrap_retired: bool = False
    answer_media_detached: bool = False
    install_secrets_cleared: bool = False
    pairing_ready: bool = False
    paired: bool = False

    def validate(self) -> None:
        for name in (
            "network_ready",
            "install_media_ready",
            "vm_running",
            "guest_booted",
            "guest_bootstrap_ready",
            "agent_device_enrolled",
            "agent_package_ready",
            "agent_service_ready",
            "agent_healthy",
            "bootstrap_retired",
            "answer_media_detached",
            "install_secrets_cleared",
            "pairing_ready",
            "paired",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"provision observation must be boolean: {name}")
        if self.vm_id is not None:
            if not isinstance(self.vm_id, str) or not self.vm_id:
                raise ValueError("provision observation vm_id must be a canonical GUID or null")
            try:
                canonical_vm_id = str(uuid.UUID(self.vm_id))
            except (ValueError, AttributeError) as exc:
                raise ValueError(
                    "provision observation vm_id must be a canonical GUID or null"
                ) from exc
            if self.vm_id != canonical_vm_id:
                raise ValueError(
                    "provision observation vm_id must use canonical lowercase GUID form"
                )


@dataclass(frozen=True)
class ProvisionContext:
    instance_id: str
    config: WindowsVMConfig
    host: HyperVHostState
    image: WindowsImage | None
    observation: ProvisionObservation = field(default_factory=ProvisionObservation)


@dataclass(frozen=True)
class TransitionResult:
    record: ProvisionRecord
    action: str
    requires_operator_approval: bool = False
    requires_reboot: bool = False


class ProvisioningOrchestrator:
    """Persistent reconcile-oriented provisioning state machine.

    Ordinary mutation actions do not advance durable state. A state advances only
    after observation proves the previous mutation reached its postcondition.

    Agent device enrollment is a mandatory pre-service checkpoint. The guest
    bootstrap state cannot advance to HMS Agent installation until observation
    proves the stable Bridge/guest device credential has been enrolled. The
    existing AGENT_INSTALLING state is the durable checkpoint for that proof.
    Inside AGENT_INSTALLING, the attested Agent package must first be staged,
    published and reverified before service installation is permitted.

    Bootstrap retirement is a special two-phase boundary: the runtime first
    persists BOOTSTRAP_RETIRING, then executes the final credentialed guest
    action, then persists BOOTSTRAP_RETIRED after the guest script verifies its
    own postconditions. If the process crashes in that narrow window, automatic
    credential reuse is prohibited and recovery waits for an external proof.

    Every reconcile-driven durable advance is a compare-and-swap against the
    exact state observed at the start of this call. Concurrent reconcilers may
    observe stale state, but a stale writer cannot regress or skip over a newer
    checkpoint. Host and observation evidence are type-exact before any state
    decision, and VM identity evidence must be a canonical GUID, so coercible
    values cannot satisfy provisioning gates.
    """

    def __init__(self, state_path: Path) -> None:
        self.store = ProvisionStateStore(state_path)

    def current(self, instance_id: str) -> ProvisionRecord:
        return self.store.initialize(instance_id=instance_id)

    def _advance(
        self,
        record: ProvisionRecord,
        *,
        instance_id: str,
        state: ProvisionState,
        reason: str | None = None,
        resume_state: ProvisionState | None = None,
        last_error: str | None = None,
        increment_attempt: bool = False,
    ) -> ProvisionRecord:
        return self.store.transition_checked(
            instance_id=instance_id,
            expected_state=record.state,
            state=state,
            reason=reason,
            resume_state=resume_state,
            last_error=last_error,
            increment_attempt=increment_attempt,
        )

    def reconcile(self, context: ProvisionContext) -> TransitionResult:
        if not isinstance(context.instance_id, str) or not context.instance_id.strip():
            raise ValueError("provision context instance_id is required")
        context.config.validate()
        context.host.validate()
        context.observation.validate()

        record = self.current(context.instance_id)
        observed = context.observation

        if record.state in {ProvisionState.READY, ProvisionState.FAILED}:
            return TransitionResult(record=record, action="NOOP")

        if record.state is ProvisionState.IDLE:
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.PREFLIGHT,
                increment_attempt=True,
            )
            return TransitionResult(next_record, "RUN_PREFLIGHT")

        if record.state is ProvisionState.PREFLIGHT:
            if not context.host.is_windows:
                failed = self._advance(
                    record,
                    instance_id=context.instance_id,
                    state=ProvisionState.FAILED,
                    last_error="Windows host required",
                )
                return TransitionResult(failed, "BLOCK_UNSUPPORTED_HOST")
            if not context.host.virtualization_firmware_enabled or not context.host.hyperv_available:
                failed = self._advance(
                    record,
                    instance_id=context.instance_id,
                    state=ProvisionState.FAILED,
                    last_error="Hyper-V or firmware virtualization unavailable",
                )
                return TransitionResult(failed, "BLOCK_HYPERV_UNAVAILABLE")
            if not context.host.hyperv_enabled:
                pending = self._advance(
                    record,
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
                pending = self._advance(
                    record,
                    instance_id=context.instance_id,
                    state=ProvisionState.REBOOT_PENDING,
                    reason="hyperv_restart_required",
                    resume_state=ProvisionState.PREFLIGHT,
                )
                return TransitionResult(pending, "REQUEST_REBOOT", requires_reboot=True)
            if context.image is None:
                waiting = self._advance(
                    record,
                    instance_id=context.instance_id,
                    state=ProvisionState.PREFLIGHT,
                    reason="windows_image_required",
                )
                return TransitionResult(waiting, "WAIT_FOR_WINDOWS_IMAGE")
            try:
                context.image.validate()
            except (FileNotFoundError, ValueError) as exc:
                failed = self._advance(
                    record,
                    instance_id=context.instance_id,
                    state=ProvisionState.FAILED,
                    last_error=f"Windows image validation failed: {exc}",
                )
                return TransitionResult(failed, "BLOCK_INVALID_WINDOWS_IMAGE")
            ready = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.IMAGE_READY,
                reason=None,
            )
            return TransitionResult(ready, "IMAGE_VERIFIED")

        if record.state is ProvisionState.NEED_ELEVATION:
            return TransitionResult(
                record,
                "WAIT_FOR_OPERATOR_APPROVAL",
                requires_operator_approval=True,
            )

        if record.state is ProvisionState.REBOOT_PENDING:
            return TransitionResult(record, "WAIT_FOR_REBOOT", requires_reboot=True)

        if record.state is ProvisionState.IMAGE_READY:
            if not observed.network_ready:
                return TransitionResult(record, "ENSURE_INTERNAL_NAT_NETWORK")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.NETWORK_READY,
            )
            return TransitionResult(next_record, "NETWORK_VERIFIED")

        if record.state is ProvisionState.NETWORK_READY:
            if observed.vm_id is None:
                return TransitionResult(record, "ENSURE_VM")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.VM_CREATED,
            )
            return TransitionResult(next_record, "VM_VERIFIED")

        if record.state is ProvisionState.VM_CREATED:
            if not observed.install_media_ready:
                return TransitionResult(record, "ATTACH_INSTALL_MEDIA")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.INSTALL_MEDIA_READY,
            )
            return TransitionResult(next_record, "INSTALL_MEDIA_VERIFIED")

        if record.state is ProvisionState.INSTALL_MEDIA_READY:
            if not observed.vm_running:
                return TransitionResult(record, "START_UNATTENDED_INSTALL")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.OS_INSTALLING,
            )
            return TransitionResult(next_record, "OS_INSTALL_STARTED")

        if record.state is ProvisionState.OS_INSTALLING:
            if not observed.guest_booted:
                return TransitionResult(record, "WAIT_FOR_GUEST_HEARTBEAT")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.GUEST_BOOTED,
            )
            return TransitionResult(next_record, "GUEST_BOOT_VERIFIED")

        if record.state is ProvisionState.GUEST_BOOTED:
            if not observed.guest_bootstrap_ready:
                return TransitionResult(record, "BOOTSTRAP_GUEST_WITH_POWERSHELL_DIRECT")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.GUEST_BOOTSTRAP,
            )
            return TransitionResult(next_record, "GUEST_BOOTSTRAP_VERIFIED")

        if record.state is ProvisionState.GUEST_BOOTSTRAP:
            if not observed.agent_device_enrolled:
                return TransitionResult(record, "ENROLL_AGENT_DEVICE")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.AGENT_INSTALLING,
                reason="agent_device_enrollment_verified",
            )
            return TransitionResult(next_record, "AGENT_DEVICE_ENROLLMENT_VERIFIED")

        if record.state is ProvisionState.AGENT_INSTALLING:
            if not observed.agent_package_ready:
                return TransitionResult(record, "STAGE_HMS_AGENT_PACKAGE")
            if not observed.agent_service_ready:
                return TransitionResult(record, "INSTALL_HMS_AGENT")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.AGENT_SERVICE_READY,
            )
            return TransitionResult(next_record, "AGENT_SERVICE_VERIFIED")

        if record.state is ProvisionState.AGENT_SERVICE_READY:
            if not observed.agent_healthy:
                return TransitionResult(record, "WAIT_FOR_AGENT_APPLICATION_HEALTH")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.AGENT_HEALTHY,
            )
            return TransitionResult(next_record, "AGENT_APPLICATION_HEALTH_VERIFIED")

        if record.state is ProvisionState.AGENT_HEALTHY:
            return TransitionResult(record, "RETIRE_BOOTSTRAP_ACCOUNT")

        if record.state is ProvisionState.BOOTSTRAP_RETIRING:
            if not observed.bootstrap_retired:
                return TransitionResult(record, "WAIT_FOR_BOOTSTRAP_RETIREMENT_PROOF")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.BOOTSTRAP_RETIRED,
            )
            return TransitionResult(next_record, "BOOTSTRAP_RETIREMENT_VERIFIED")

        if record.state is ProvisionState.BOOTSTRAP_RETIRED:
            if not observed.answer_media_detached:
                return TransitionResult(record, "DETACH_ANSWER_MEDIA")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.ANSWER_MEDIA_DETACHED,
            )
            return TransitionResult(next_record, "ANSWER_MEDIA_DETACH_VERIFIED")

        if record.state is ProvisionState.ANSWER_MEDIA_DETACHED:
            if not observed.install_secrets_cleared:
                return TransitionResult(record, "CLEAR_INSTALL_SECRETS")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.INSTALL_SECRETS_CLEARED,
            )
            return TransitionResult(next_record, "INSTALL_SECRETS_CLEAR_VERIFIED")

        if record.state is ProvisionState.INSTALL_SECRETS_CLEARED:
            if not observed.pairing_ready:
                return TransitionResult(record, "CREATE_ONE_TIME_PAIRING")
            next_record = self._advance(
                record,
                instance_id=context.instance_id,
                state=ProvisionState.PAIRING_PENDING,
            )
            return TransitionResult(next_record, "PAIRING_RECORD_VERIFIED")

        if record.state is ProvisionState.PAIRING_PENDING:
            # A consumed one-time grant is insufficient to prove the principal
            # binding is durable. READY is committed only by the authenticated
            # principal-pairing production authority after exact binding
            # publication and fresh pairing/Agent revalidation.
            return TransitionResult(record, "WAIT_FOR_PRINCIPAL_BINDING")

        return TransitionResult(record, "RECONCILE_EXTERNAL_SIGNAL")

    def mark_guest_booted(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition_checked(
            instance_id=instance_id,
            expected_state=ProvisionState.OS_INSTALLING,
            state=ProvisionState.GUEST_BOOTED,
        )

    def mark_agent_healthy(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition_checked(
            instance_id=instance_id,
            expected_state=ProvisionState.AGENT_SERVICE_READY,
            state=ProvisionState.AGENT_HEALTHY,
        )

    def begin_bootstrap_retirement(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition_checked(
            instance_id=instance_id,
            expected_state=ProvisionState.AGENT_HEALTHY,
            state=ProvisionState.BOOTSTRAP_RETIRING,
            reason="final_credentialed_guest_action",
        )

    def mark_bootstrap_retired(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition_checked(
            instance_id=instance_id,
            expected_state=ProvisionState.BOOTSTRAP_RETIRING,
            state=ProvisionState.BOOTSTRAP_RETIRED,
        )

    def mark_answer_media_detached(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition_checked(
            instance_id=instance_id,
            expected_state=ProvisionState.BOOTSTRAP_RETIRED,
            state=ProvisionState.ANSWER_MEDIA_DETACHED,
        )

    def mark_install_secrets_cleared(self, instance_id: str) -> ProvisionRecord:
        return self.store.transition_checked(
            instance_id=instance_id,
            expected_state=ProvisionState.ANSWER_MEDIA_DETACHED,
            state=ProvisionState.INSTALL_SECRETS_CLEARED,
        )

    def mark_ready(self, instance_id: str) -> ProvisionRecord:
        raise NotImplementedError(
            "READY is committed only by principal-pairing binding authority"
        )
