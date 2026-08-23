from pathlib import Path

from hms_gpt_vps.hyperv_executor import build_ensure_vm_script
from hms_gpt_vps.instance_registry import InstanceRegistry, VMRecord
from hms_gpt_vps.windows_provisioner import WindowsVMConfig


def test_registry_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "instances.json"
    registry = InstanceRegistry(path)
    record = VMRecord(
        instance_id="HMS-VM-000001",
        vm_name="HMS-GPT-VPS-01",
        backend="hyperv-windows",
        phase="host_ready",
        workspace_path=r"C:\HMS-Workspace",
    )
    registry.upsert(record)
    assert registry.load()[record.instance_id] == record


def test_registry_upsert_is_stable(tmp_path: Path) -> None:
    path = tmp_path / "instances.json"
    registry = InstanceRegistry(path)
    first = VMRecord("id-1", "vm-1", "hyperv-windows", "host_ready", r"C:\HMS-Workspace")
    second = VMRecord("id-1", "vm-1", "hyperv-windows", "vm_creating", r"C:\HMS-Workspace")
    registry.upsert(first)
    registry.upsert(second)
    assert registry.load() == {"id-1": second}


def test_hyperv_script_is_idempotent_shape() -> None:
    config = WindowsVMConfig(name="HMS-TEST-VM")
    script = build_ensure_vm_script(config)
    assert "Get-VM -Name $vmName" in script
    assert "if ($null -eq $vm)" in script
    assert "New-VM -Name $vmName" in script
    assert "Set-VMProcessor" in script
    assert "AutomaticCheckpointsEnabled $false" in script
