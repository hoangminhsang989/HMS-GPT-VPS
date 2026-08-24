from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_managed_agent_runtime_uses_only_vm_id_bound_guest_operations() -> None:
    source = _source("src/hms_gpt_vps/managed_agent_provisioning_runtime.py")

    required = (
        "probe_guest_service_interface_enabled_by_id(",
        "restore_guest_service_interface_state_by_id(",
        "reset_owned_agent_package_staging_by_id(",
        "transfer_agent_package_to_guest_by_id(",
        "probe_agent_package_ready_by_id(",
        "install_agent_service_by_id(",
        "observe_agent_post_install_by_id(",
    )
    for marker in required:
        assert marker in source

    forbidden = (
        "probe_guest_service_interface_enabled(",
        "restore_guest_service_interface_state(",
        "reset_owned_agent_package_staging(",
        "transfer_agent_package_to_guest(",
        "probe_agent_package_ready(",
        "install_agent_service(",
        "AgentPostInstallObserver(",
        "run_vm_powershell_json(",
    )
    for marker in forbidden:
        assert marker not in source


def test_managed_hyperv_qualification_uses_vm_id_bound_enrollment_probe() -> None:
    source = _source("src/hms_gpt_vps/managed_hyperv_agent_qualification.py")

    assert "probe_agent_device_enrollment_by_id(" in source
    assert "probe_agent_device_enrollment(" not in source


def test_managed_vm_operations_never_target_mutable_vm_name() -> None:
    source = _source("src/hms_gpt_vps/managed_vm_id_operations.py")

    assert "run_vm_powershell_json_by_id(" in source
    assert "Copy-VMFile -VM $managedVm" in source
    assert "Get-VMIntegrationService -VM $managedVm" in source
    assert "Copy-VMFile -Name" not in source
    assert "Get-VMIntegrationService -VMName" not in source
    assert "Enable-VMIntegrationService -VMName" not in source
    assert "Disable-VMIntegrationService -VMName" not in source
