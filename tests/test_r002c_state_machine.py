from pathlib import Path

from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps.provisioning import ProvisionContext, ProvisioningOrchestrator
from hms_gpt_vps.unattend import UnattendConfig, generate_unattend
from hms_gpt_vps.windows_provisioner import HyperVHostState, WindowsVMConfig


def ready_host() -> HyperVHostState:
    return HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=True,
        virtualization_firmware_enabled=True,
        restart_required=False,
    )


def test_state_store_round_trip(tmp_path: Path) -> None:
    store = ProvisionStateStore(tmp_path / "provision.json")
    saved = store.transition(
        instance_id="hms-01",
        state=ProvisionState.PREFLIGHT,
        increment_attempt=True,
    )
    assert saved.attempt == 1
    loaded = store.load()
    assert loaded is not None
    assert loaded.state is ProvisionState.PREFLIGHT
    assert loaded.instance_id == "hms-01"


def test_orchestrator_requires_elevation_when_hyperv_disabled(tmp_path: Path) -> None:
    orchestrator = ProvisioningOrchestrator(tmp_path / "provision.json")
    host = HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=False,
        virtualization_firmware_enabled=True,
        restart_required=False,
    )
    context = ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=host,
        image=None,
    )
    assert orchestrator.reconcile(context).record.state is ProvisionState.PREFLIGHT
    result = orchestrator.reconcile(context)
    assert result.record.state is ProvisionState.NEED_ELEVATION
    assert result.requires_operator_approval is True


def test_orchestrator_waits_for_image_after_ready_preflight(tmp_path: Path) -> None:
    orchestrator = ProvisioningOrchestrator(tmp_path / "provision.json")
    context = ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=ready_host(),
        image=None,
    )
    orchestrator.reconcile(context)
    result = orchestrator.reconcile(context)
    assert result.record.state is ProvisionState.PREFLIGHT
    assert result.action == "WAIT_FOR_WINDOWS_IMAGE"


def test_unattend_contains_no_reusable_secret_fields() -> None:
    xml = generate_unattend(UnattendConfig(computer_name="HMSVPS01"))
    lowered = xml.lower()
    assert "productkey" not in lowered
    assert "password" not in lowered
    assert "api_key" not in lowered
    assert "pair" not in lowered
    assert "HMSVPS01" in xml
