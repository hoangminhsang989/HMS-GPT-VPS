from pathlib import Path

import pytest

from hms_gpt_vps.hyperv_network import HyperVNetworkConfig, build_ensure_internal_nat_script
from hms_gpt_vps.hyperv_vm import build_reconcile_vm_script
from hms_gpt_vps.install_media import build_attach_windows_iso_script
from hms_gpt_vps.instance_registry import InstanceRegistry, VMRecord
from hms_gpt_vps.powershell import ps_literal
from hms_gpt_vps.windows_provisioner import WindowsVMConfig


def test_powershell_literal_escapes_single_quotes() -> None:
    assert ps_literal("VM'Name") == "'VM''Name'"


def test_default_network_is_private_internal_nat() -> None:
    config = HyperVNetworkConfig()
    config.validate()
    assert config.switch_name == "HMS-GPT-VPS-Internal"
    assert config.nat_name == "HMS-GPT-VPS-NAT"
    assert config.guest_ipv4 != config.gateway


def test_network_rejects_guest_equal_to_gateway() -> None:
    with pytest.raises(ValueError):
        HyperVNetworkConfig(guest_ipv4="172.29.240.1").validate()


def test_network_script_has_no_inbound_static_mapping() -> None:
    script = build_ensure_internal_nat_script(HyperVNetworkConfig())
    assert "New-VMSwitch" in script
    assert "-SwitchType Internal" in script
    assert "New-NetNat" in script
    assert "New-NetNatStaticMapping" not in script
    assert "Add-NetNatStaticMapping" not in script


def test_vm_reconcile_is_identity_bound_and_never_auto_stops() -> None:
    script = build_reconcile_vm_script(
        WindowsVMConfig(),
        expected_vm_id="11111111-2222-3333-4444-555555555555",
    )
    assert "Get-VM -Id" in script
    assert "VM identity conflict" in script
    assert "SecureBootTemplate MicrosoftWindows" in script
    assert "automatic stop is forbidden" in script
    assert "Stop-VM" not in script


def test_install_media_sets_dvd_as_first_boot_without_forced_stop(tmp_path: Path) -> None:
    iso = tmp_path / "windows.iso"
    iso.write_bytes(b"placeholder")
    script = build_attach_windows_iso_script(WindowsVMConfig(), iso)
    assert "Add-VMDvdDrive" in script
    assert "Set-VMDvdDrive" in script
    assert "-FirstBootDevice $dvd" in script
    assert "Stop-VM" not in script


def test_instance_registry_refuses_vm_id_replacement(tmp_path: Path) -> None:
    registry = InstanceRegistry(tmp_path / "instances.json")
    registry.upsert(
        VMRecord(
            instance_id="hms-01",
            vm_name="HMS-GPT-VPS-01",
            backend="hyperv",
            phase="vm_created",
            workspace_path=r"C:\HMS-Workspace",
            vm_id="11111111-2222-3333-4444-555555555555",
        )
    )
    with pytest.raises(ValueError):
        registry.upsert(
            VMRecord(
                instance_id="hms-01",
                vm_name="HMS-GPT-VPS-01",
                backend="hyperv",
                phase="vm_created",
                workspace_path=r"C:\HMS-Workspace",
                vm_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            )
        )


def test_windows_vm_default_switch_matches_isolated_network() -> None:
    assert WindowsVMConfig().switch_name == HyperVNetworkConfig().switch_name
