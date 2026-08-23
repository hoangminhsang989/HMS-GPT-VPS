from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


@dataclass(frozen=True)
class VMIdentity:
    vm_name: str
    vm_id: str | None = None


def build_reconcile_vm_script(
    config: WindowsVMConfig,
    *,
    expected_vm_id: str | None = None,
) -> str:
    """Build an idempotent Hyper-V Generation-2 VM reconcile script.

    If an expected VMId is known, a same-name VM with a different VMId is
    treated as an identity conflict. The reconciler never stops a running VM;
    settings that require an Off state fail closed instead.
    """
    config.validate()
    vm_dir = config.vm_root / config.name
    vhd_path = vm_dir / f"{config.name}.vhdx"

    vm_name = ps_literal(config.name)
    vm_root = ps_literal(vm_dir)
    vhd = ps_literal(vhd_path)
    switch = ps_literal(config.switch_name)
    expected_id = ps_literal(expected_vm_id) if expected_vm_id else "$null"

    return f"""
$ErrorActionPreference = 'Stop'
$changed = $false
$vmName = {vm_name}
$vmRoot = {vm_root}
$vhdPath = {vhd}
$switchName = {switch}
$expectedVmId = {expected_id}

if (-not (Test-Path $vmRoot)) {{
  New-Item -ItemType Directory -Path $vmRoot -Force | Out-Null
  $changed = $true
}}

$vmByName = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if ($null -ne $expectedVmId) {{
  $vmById = Get-VM -Id $expectedVmId -ErrorAction SilentlyContinue
  if ($null -eq $vmById) {{
    if ($null -ne $vmByName) {{
      throw "VM identity conflict: name exists but expected VMId was not found"
    }}
  }} elseif ($vmById.Name -ne $vmName) {{
    throw "VM identity conflict: expected VMId belongs to a different name"
  }}
}}

$vm = $vmByName
if ($null -eq $vm) {{
  if (-not (Test-Path $vhdPath)) {{
    New-VHD -Path $vhdPath -Dynamic -SizeBytes {config.disk_size_gb}GB | Out-Null
    $changed = $true
  }}
  New-VM -Name $vmName -Generation {config.generation} -MemoryStartupBytes {config.memory_mb}MB -VHDPath $vhdPath -Path $vmRoot -SwitchName $switchName | Out-Null
  $vm = Get-VM -Name $vmName -ErrorAction Stop
  $changed = $true
}}

if ($null -ne $expectedVmId -and $vm.Id.Guid -ne $expectedVmId) {{
  throw "VM identity conflict after lookup"
}}

if ($vm.State -ne 'Off') {{
  throw "VM must be Off before static reconciliation; automatic stop is forbidden"
}}

Set-VMProcessor -VMName $vmName -Count {config.cpu_count}
Set-VMMemory -VMName $vmName -StartupBytes {config.memory_mb}MB -DynamicMemoryEnabled $false
Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false
Set-VMFirmware -VMName $vmName -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows

$adapter = Get-VMNetworkAdapter -VMName $vmName | Select-Object -First 1
if ($null -eq $adapter) {{
  Add-VMNetworkAdapter -VMName $vmName -SwitchName $switchName | Out-Null
  $changed = $true
}} elseif ($adapter.SwitchName -ne $switchName) {{
  Connect-VMNetworkAdapter -VMName $vmName -Name $adapter.Name -SwitchName $switchName
  $changed = $true
}}

[pscustomobject]@{{
  changed = $changed
  vm_name = $vmName
  vm_id = $vm.Id.Guid
  state = $vm.State.ToString()
  vhd_path = $vhdPath
  switch_name = $switchName
}}
""".strip()


def reconcile_vm(
    config: WindowsVMConfig,
    *,
    expected_vm_id: str | None = None,
) -> dict[str, object]:
    return run_powershell_json(
        build_reconcile_vm_script(config, expected_vm_id=expected_vm_id),
        timeout_seconds=180,
    )


def vhd_path_for(config: WindowsVMConfig) -> Path:
    config.validate()
    return config.vm_root / config.name / f"{config.name}.vhdx"
