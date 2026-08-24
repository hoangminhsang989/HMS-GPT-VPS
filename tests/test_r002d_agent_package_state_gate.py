from pathlib import Path

from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps.provisioning import (
    ProvisionContext,
    ProvisionObservation,
    ProvisioningOrchestrator,
)
from hms_gpt_vps.windows_provisioner import HyperVHostState, WindowsVMConfig


def ready_host() -> HyperVHostState:
    return HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=True,
        virtualization_firmware_enabled=True,
        restart_required=False,
    )


def context(*, package_ready: bool, service_ready: bool = False) -> ProvisionContext:
    return ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=ready_host(),
        image=None,
        observation=ProvisionObservation(
            agent_device_enrolled=True,
            agent_package_ready=package_ready,
            agent_service_ready=service_ready,
        ),
    )


def orchestrator_at_agent_installing(tmp_path: Path) -> ProvisioningOrchestrator:
    state_path = tmp_path / "provision.json"
    ProvisionStateStore(state_path).transition(
        instance_id="hms-01",
        state=ProvisionState.AGENT_INSTALLING,
        reason="agent_device_enrollment_verified",
    )
    return ProvisioningOrchestrator(state_path)


def test_agent_installing_stages_verified_package_before_service_install(tmp_path: Path) -> None:
    orchestrator = orchestrator_at_agent_installing(tmp_path)

    result = orchestrator.reconcile(context(package_ready=False))

    assert result.record.state is ProvisionState.AGENT_INSTALLING
    assert result.action == "STAGE_HMS_AGENT_PACKAGE"


def test_agent_installing_allows_service_install_only_after_package_ready(tmp_path: Path) -> None:
    orchestrator = orchestrator_at_agent_installing(tmp_path)

    result = orchestrator.reconcile(context(package_ready=True))

    assert result.record.state is ProvisionState.AGENT_INSTALLING
    assert result.action == "INSTALL_HMS_AGENT"


def test_agent_installing_advances_only_when_package_and_service_are_both_ready(
    tmp_path: Path,
) -> None:
    orchestrator = orchestrator_at_agent_installing(tmp_path)

    result = orchestrator.reconcile(context(package_ready=True, service_ready=True))

    assert result.record.state is ProvisionState.AGENT_SERVICE_READY
    assert result.action == "AGENT_SERVICE_VERIFIED"
