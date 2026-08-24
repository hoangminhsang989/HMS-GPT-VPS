from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import uuid

from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


_RECONCILE_VM_RESULT_KEYS = frozenset(
    {"changed", "vm_name", "vm_id", "state", "vhd_path", "switch_name", "tpm_enabled"}
)


def _canonical_vm_id(value: object, label: str = "VMId") -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a canonical GUID string")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{label} must be a canonical GUID string") from exc
    if value != canonical:
        raise ValueError(f"{label} must use canonical lowercase GUID form")
    return canonical


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

    The managed Windows baseline enables Secure Boot plus a local-key-protected
    virtual TPM so a Windows 11 guest satisfies Hyper-V security requirements.
    """
    config.validate()
    if expected_vm_id is not None:
        expected_vm_id = _canonical_vm_id(expected_vm_id, "expected VMId")
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

$security = Get-VMSecurity -VMName $vmName
if (-not $security.TpmEnabled) {{
  Set-VMKeyProtector -VMName $vmName -NewLocalKeyProtector
  Enable-VMTPM -VMName $vmName
  $changed = $true
}}

$adapter = Get-VMNetworkAdapter -VMName $vmName | Select-Object -First 1
if ($null -eq $adapter) {{
  Add-VMNetworkAdapter -VMName $vmName -SwitchName $switchName | Out-Null
  $changed = $true
}} elseif ($adapter.SwitchName -ne $switchName) {{
  Connect-VMNetworkAdapter -VMName $vmName -Name $adapter.Name -SwitchName $switchName
  $changed = $true
}}

$security = Get-VMSecurity -VMName $vmName
[pscustomobject]@{{
  changed = [bool]$changed
  vm_name = $vmName
  vm_id = $vm.Id.Guid
  state = $vm.State.ToString()
  vhd_path = $vhdPath
  switch_name = $switchName
  tpm_enabled = [bool]$security.TpmEnabled
}}
""".strip()


def reconcile_vm(
    config: WindowsVMConfig,
    *,
    expected_vm_id: str | None = None,
) -> dict[str, object]:
    config.validate()
    if expected_vm_id is not None:
        expected_vm_id = _canonical_vm_id(expected_vm_id, "expected VMId")
    payload = run_powershell_json(
        build_reconcile_vm_script(config, expected_vm_id=expected_vm_id),
        timeout_seconds=180,
    )
    if not isinstance(payload, dict) or set(payload) != _RECONCILE_VM_RESULT_KEYS:
        raise ValueError("Hyper-V reconcile result schema is invalid")
    if not isinstance(payload["changed"], bool):
        raise ValueError("Hyper-V reconcile changed evidence must be boolean")
    if not isinstance(payload["tpm_enabled"], bool):
        raise ValueError("Hyper-V reconcile TPM evidence must be boolean")
    if payload["tpm_enabled"] is not True:
        raise ValueError("Hyper-V reconcile did not prove TPM enabled")
    if payload["vm_name"] != config.name:
        raise ValueError("Hyper-V reconcile VM name evidence mismatch")
    if payload["switch_name"] != config.switch_name:
        raise ValueError("Hyper-V reconcile switch evidence mismatch")
    if payload["vhd_path"] != str(vhd_path_for(config)):
        raise ValueError("Hyper-V reconcile VHD path evidence mismatch")
    if payload["state"] != "Off":
        raise ValueError("Hyper-V reconcile VM state evidence must be Off")
    vm_id = _canonical_vm_id(payload["vm_id"])
    if expected_vm_id is not None and vm_id != expected_vm_id:
        raise ValueError("Hyper-V reconcile VMId evidence mismatch")
    return {
        "changed": payload["changed"],
        "vm_name": config.name,
        "vm_id": vm_id,
        "state": "Off",
        "vhd_path": str(vhd_path_for(config)),
        "switch_name": config.switch_name,
        "tpm_enabled": True,
    }


def vhd_path_for(config: WindowsVMConfig) -> Path:
    config.validate()
    return config.vm_root / config.name / f"{config.name}.vhdx"
