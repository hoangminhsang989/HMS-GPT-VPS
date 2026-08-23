from pathlib import Path

import pytest

from hms_gpt_vps.windows_provisioner import (
    HyperVHostState,
    ProvisionPhase,
    WindowsVMConfig,
    build_provision_plan,
)


def test_default_windows_vm_config_is_valid() -> None:
    WindowsVMConfig().validate()


def test_vm_config_rejects_too_little_memory() -> None:
    with pytest.raises(ValueError):
        WindowsVMConfig(memory_mb=2048).validate()


def test_non_windows_host_is_blocked() -> None:
    host = HyperVHostState(
        is_windows=False,
        hyperv_available=False,
        hyperv_enabled=False,
        virtualization_firmware_enabled=False,
    )
    plan = build_provision_plan(host, WindowsVMConfig())
    assert plan.phase is ProvisionPhase.PREFLIGHT
    assert plan.actions == ("BLOCK: Windows host required",)


def test_disabled_hyperv_requires_elevation_and_restart() -> None:
    host = HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=False,
        virtualization_firmware_enabled=True,
    )
    plan = build_provision_plan(host, WindowsVMConfig())
    assert plan.requires_elevation is True
    assert plan.requires_restart is True
    assert plan.phase is ProvisionPhase.PREFLIGHT


def test_ready_host_produces_windows_vm_plan() -> None:
    host = HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=True,
        virtualization_firmware_enabled=True,
    )
    config = WindowsVMConfig(vm_root=Path(r"D:\HMS-VMs"))
    plan = build_provision_plan(host, config)
    assert plan.phase is ProvisionPhase.HOST_READY
    assert any(action.startswith("CREATE_VM:") for action in plan.actions)
    assert "DISABLE_IMPLICIT_HOST_SHARES" in plan.actions
    assert any("C:\\HMS-Workspace" in action for action in plan.actions)
