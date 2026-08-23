from pathlib import Path

from hms_gpt_vps.provision_state import ProvisionState
from hms_gpt_vps.provisioning import (
    ProvisionContext,
    ProvisionObservation,
    ProvisioningOrchestrator,
)
from hms_gpt_vps.windows_image import WindowsImage
from hms_gpt_vps.windows_provisioner import HyperVHostState, WindowsVMConfig


def ready_host() -> HyperVHostState:
    return HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=True,
        virtualization_firmware_enabled=True,
        restart_required=False,
    )


def make_iso(tmp_path: Path) -> WindowsImage:
    path = tmp_path / "windows.iso"
    path.write_bytes(b"placeholder")
    return WindowsImage(path)


def advance_to_image_ready(tmp_path: Path) -> tuple[ProvisioningOrchestrator, ProvisionContext]:
    orchestrator = ProvisioningOrchestrator(tmp_path / "provision.json")
    context = ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=ready_host(),
        image=make_iso(tmp_path),
    )
    assert orchestrator.reconcile(context).record.state is ProvisionState.PREFLIGHT
    result = orchestrator.reconcile(context)
    assert result.record.state is ProvisionState.IMAGE_READY
    return orchestrator, context


def test_network_mutation_does_not_advance_without_observed_postcondition(tmp_path: Path) -> None:
    orchestrator, context = advance_to_image_ready(tmp_path)
    result = orchestrator.reconcile(context)
    assert result.record.state is ProvisionState.IMAGE_READY
    assert result.action == "ENSURE_INTERNAL_NAT_NETWORK"


def test_network_advances_only_after_observation(tmp_path: Path) -> None:
    orchestrator, context = advance_to_image_ready(tmp_path)
    observed = ProvisionContext(
        instance_id=context.instance_id,
        config=context.config,
        host=context.host,
        image=context.image,
        observation=ProvisionObservation(network_ready=True),
    )
    result = orchestrator.reconcile(observed)
    assert result.record.state is ProvisionState.NETWORK_READY
    assert result.action == "NETWORK_VERIFIED"


def test_vm_mutation_does_not_advance_without_vm_id(tmp_path: Path) -> None:
    orchestrator, context = advance_to_image_ready(tmp_path)
    context_network = ProvisionContext(
        instance_id=context.instance_id,
        config=context.config,
        host=context.host,
        image=context.image,
        observation=ProvisionObservation(network_ready=True),
    )
    assert orchestrator.reconcile(context_network).record.state is ProvisionState.NETWORK_READY
    result = orchestrator.reconcile(context_network)
    assert result.record.state is ProvisionState.NETWORK_READY
    assert result.action == "ENSURE_VM"


def test_vm_advances_only_after_stable_vm_identity_is_observed(tmp_path: Path) -> None:
    orchestrator, context = advance_to_image_ready(tmp_path)
    context_network = ProvisionContext(
        instance_id=context.instance_id,
        config=context.config,
        host=context.host,
        image=context.image,
        observation=ProvisionObservation(network_ready=True),
    )
    orchestrator.reconcile(context_network)
    context_vm = ProvisionContext(
        instance_id=context.instance_id,
        config=context.config,
        host=context.host,
        image=context.image,
        observation=ProvisionObservation(
            network_ready=True,
            vm_id="11111111-2222-3333-4444-555555555555",
        ),
    )
    result = orchestrator.reconcile(context_vm)
    assert result.record.state is ProvisionState.VM_CREATED
    assert result.action == "VM_VERIFIED"


def test_install_media_mutation_does_not_advance_before_readback(tmp_path: Path) -> None:
    orchestrator, context = advance_to_image_ready(tmp_path)
    network = ProvisionContext(
        instance_id=context.instance_id,
        config=context.config,
        host=context.host,
        image=context.image,
        observation=ProvisionObservation(network_ready=True),
    )
    orchestrator.reconcile(network)
    vm = ProvisionContext(
        instance_id=context.instance_id,
        config=context.config,
        host=context.host,
        image=context.image,
        observation=ProvisionObservation(network_ready=True, vm_id="vm-id"),
    )
    orchestrator.reconcile(vm)
    result = orchestrator.reconcile(vm)
    assert result.record.state is ProvisionState.VM_CREATED
    assert result.action == "ATTACH_INSTALL_MEDIA"
