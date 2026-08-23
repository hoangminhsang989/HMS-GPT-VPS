from __future__ import annotations

from pathlib import Path

from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


def build_attach_windows_iso_script(config: WindowsVMConfig, iso_path: Path) -> str:
    """Build an idempotent ISO attach + first-boot-device script.

    The VM must be Off. The function never stops or resets a running VM.
    """
    config.validate()
    if iso_path.suffix.lower() != ".iso":
        raise ValueError("Windows installation media must be an ISO file")

    vm_name = ps_literal(config.name)
    iso = ps_literal(iso_path)

    return f"""
$ErrorActionPreference = 'Stop'
$changed = $false
$vmName = {vm_name}
$isoPath = {iso}

if (-not (Test-Path $isoPath)) {{
  throw "Windows ISO not found"
}}

$vm = Get-VM -Name $vmName -ErrorAction Stop
if ($vm.State -ne 'Off') {{
  throw "VM must be Off before install media reconciliation; automatic stop is forbidden"
}}

$dvd = Get-VMDvdDrive -VMName $vmName -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $dvd) {{
  Add-VMDvdDrive -VMName $vmName -Path $isoPath | Out-Null
  $dvd = Get-VMDvdDrive -VMName $vmName -ErrorAction Stop | Select-Object -First 1
  $changed = $true
}} elseif ($dvd.Path -ne $isoPath) {{
  Set-VMDvdDrive -VMName $vmName -ControllerNumber $dvd.ControllerNumber -ControllerLocation $dvd.ControllerLocation -Path $isoPath
  $dvd = Get-VMDvdDrive -VMName $vmName -ErrorAction Stop | Select-Object -First 1
  $changed = $true
}}

Set-VMFirmware -VMName $vmName -FirstBootDevice $dvd

[pscustomobject]@{{
  changed = $changed
  vm_name = $vmName
  iso_path = $isoPath
  controller_number = $dvd.ControllerNumber
  controller_location = $dvd.ControllerLocation
}}
""".strip()


def attach_windows_iso(config: WindowsVMConfig, iso_path: Path) -> dict[str, object]:
    return run_powershell_json(
        build_attach_windows_iso_script(config, iso_path),
        timeout_seconds=90,
    )
