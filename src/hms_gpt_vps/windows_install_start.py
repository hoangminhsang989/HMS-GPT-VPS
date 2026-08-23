from __future__ import annotations

from pathlib import Path

from .hyperv_vm import vhd_path_for
from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


def build_start_unattended_install_script(
    config: WindowsVMConfig,
    windows_iso: Path,
    answer_iso: Path,
) -> str:
    """Start Windows Setup only after all destructive-target invariants hold.

    The unattend answer uses WillWipeDisk=true, so this gate verifies that the
    VM owns exactly one managed VHDX and that both intended ISO files plus the
    Windows 11 security baseline are present before starting the VM.
    """
    config.validate()
    if windows_iso.suffix.lower() != ".iso" or answer_iso.suffix.lower() != ".iso":
        raise ValueError("Windows and answer media must both be ISO files")

    vm_name = ps_literal(config.name)
    vhd = ps_literal(vhd_path_for(config))
    product = ps_literal(windows_iso)
    answer = ps_literal(answer_iso)

    return f"""
$ErrorActionPreference = 'Stop'
$vmName = {vm_name}
$managedVhd = {vhd}
$windowsIso = {product}
$answerIso = {answer}

$vm = Get-VM -Name $vmName -ErrorAction Stop
if ($vm.State -ne 'Off') {{
  throw 'VM must be Off before unattended Windows Setup starts'
}}

$hardDisks = @(Get-VMHardDiskDrive -VMName $vmName -ErrorAction Stop)
if ($hardDisks.Count -ne 1) {{
  throw 'Destructive install gate: VM must have exactly one managed hard disk'
}}
$observedVhd = [System.IO.Path]::GetFullPath($hardDisks[0].Path)
$expectedVhd = [System.IO.Path]::GetFullPath($managedVhd)
if ($observedVhd -ne $expectedVhd) {{
  throw 'Destructive install gate: attached VHDX is not the managed target'
}}

$dvds = @(Get-VMDvdDrive -VMName $vmName -ErrorAction Stop)
$productDvd = $dvds | Where-Object {{ $_.Path -eq $windowsIso }} | Select-Object -First 1
$answerDvd = $dvds | Where-Object {{ $_.Path -eq $answerIso }} | Select-Object -First 1
if ($null -eq $productDvd -or $null -eq $answerDvd) {{
  throw 'Destructive install gate: complete install bundle is not attached'
}}

$firmware = Get-VMFirmware -VMName $vmName
if ($firmware.SecureBoot -ne 'On') {{
  throw 'Destructive install gate: Secure Boot is not enabled'
}}
$security = Get-VMSecurity -VMName $vmName
if (-not $security.TpmEnabled) {{
  throw 'Destructive install gate: virtual TPM is not enabled'
}}

Set-VMFirmware -VMName $vmName -FirstBootDevice $productDvd
Start-VM -Name $vmName | Out-Null
$started = Get-VM -Name $vmName -ErrorAction Stop
if ($started.State -ne 'Running') {{
  throw 'VM did not enter Running state after Start-VM'
}}

[pscustomobject]@{{
  changed = $true
  vm_id = $started.Id.Guid
  vm_state = $started.State.ToString()
  managed_vhd = $observedVhd
  windows_iso = $productDvd.Path
  answer_iso = $answerDvd.Path
}}
""".strip()


def start_unattended_install(
    config: WindowsVMConfig,
    windows_iso: Path,
    answer_iso: Path,
) -> dict[str, object]:
    return run_powershell_json(
        build_start_unattended_install_script(config, windows_iso, answer_iso),
        timeout_seconds=90,
    )
