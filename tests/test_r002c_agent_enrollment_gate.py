from __future__ import annotations

from hms_gpt_vps.agent_device_enrollment import (
    AgentDeviceEnrollmentConfig,
    build_guest_device_enrollment_script,
)
from hms_gpt_vps.provision_state import ProvisionState
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


def context(observation: ProvisionObservation) -> ProvisionContext:
    return ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=ready_host(),
        image=None,
        observation=observation,
    )


def test_agent_install_is_durably_gated_on_device_enrollment(tmp_path) -> None:
    orchestrator = ProvisioningOrchestrator(tmp_path / "provision.json")
    orchestrator.store.transition(
        instance_id="hms-01",
        state=ProvisionState.GUEST_BOOTSTRAP,
    )

    waiting = orchestrator.reconcile(context(ProvisionObservation()))
    assert waiting.action == "ENROLL_AGENT_DEVICE"
    assert waiting.record.state is ProvisionState.GUEST_BOOTSTRAP

    enrolled = orchestrator.reconcile(
        context(ProvisionObservation(agent_device_enrolled=True))
    )
    assert enrolled.action == "AGENT_DEVICE_ENROLLMENT_VERIFIED"
    assert enrolled.record.state is ProvisionState.AGENT_INSTALLING
    assert enrolled.record.reason == "agent_device_enrollment_verified"

    package = orchestrator.reconcile(context(ProvisionObservation()))
    assert package.action == "STAGE_HMS_AGENT_PACKAGE"
    assert package.record.state is ProvisionState.AGENT_INSTALLING

    install = orchestrator.reconcile(
        context(ProvisionObservation(agent_package_ready=True))
    )
    assert install.action == "INSTALL_HMS_AGENT"
    assert install.record.state is ProvisionState.AGENT_INSTALLING

    service_ready = orchestrator.reconcile(
        context(
            ProvisionObservation(
                agent_package_ready=True,
                agent_service_ready=True,
            )
        )
    )
    assert service_ready.action == "AGENT_SERVICE_VERIFIED"
    assert service_ready.record.state is ProvisionState.AGENT_SERVICE_READY


def test_agent_device_enrollment_observation_defaults_fail_closed() -> None:
    observation = ProvisionObservation()
    assert observation.agent_device_enrolled is False
    assert observation.agent_package_ready is False


def test_guest_enrollment_reconciles_acl_on_every_retry_and_preserves_service_sid() -> None:
    script = build_guest_device_enrollment_script(
        AgentDeviceEnrollmentConfig(instance_id="hms-01")
    )

    assert "Protected Agent runtime parent must exist before device enrollment" in script
    assert "Get-Service -Name $serviceName -ErrorAction SilentlyContinue" in script
    assert '"${servicePrincipal}:(OI)(CI)M"' in script
    assert script.count("'/inheritance:r'") == 2
    assert "Failed to reconcile Agent State directory ACL" in script
    assert "Agent device credential fields do not match schema" in script
    assert "Agent enrollment payload fields do not match schema" in script
    assert "$created = $false" in script
    assert "$created = $true" in script


def test_enrollment_config_rejects_invalid_service_name() -> None:
    config = AgentDeviceEnrollmentConfig(
        instance_id="hms-01",
        service_name="HMS Agent; Remove-Item C:\\",
    )
    try:
        config.validate()
    except ValueError as exc:
        assert "service_name" in str(exc)
    else:
        raise AssertionError("invalid service_name was accepted")
