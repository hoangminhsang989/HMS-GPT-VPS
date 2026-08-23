from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


@dataclass(frozen=True)
class InstallBundleObservation:
    windows_iso_ready: bool
    answer_iso_ready: bool
    windows_iso_path: str | None = None
    answer_iso_path: str | None = None

    @property
    def ready(self) -> bool:
        return self.windows_iso_ready and self.answer_iso_ready


def build_reconcile_install_bundle_script(
    config: WindowsVMConfig,
    windows_iso: Path,
    answer_iso: Path,
) -> str:
    """Attach the product ISO and transient answer ISO without replacing unknown media.

    Both source paths must already exist. The Windows product ISO is configured
    as the first boot device. A VM containing an unrelated DVD is treated as a
    conflict so the provisioner never silently detaches operator-owned media.
    """
    config.validate()
    if windows_iso.suffix.lower() != ".iso" or answer_iso.suffix.lower() != ".iso":
        raise ValueError("both install bundle paths must be ISO files")
    if windows_iso.resolve() == answer_iso.resolve():
        raise ValueError("Windows ISO and answer ISO must be different files")

    vm_name = ps_literal(config.name)
    product = ps_literal(windows_iso)
    answer = ps_literal(answer_iso)

    return f"""
$ErrorActionPreference = 'Stop'
$changed = $false
$vmName = {vm_name}
$windowsIso = {product}
$answerIso = {answer}

if (-not (Test-Path $windowsIso)) {{ throw 'Windows product ISO not found' }}
if (-not (Test-Path $answerIso)) {{ throw 'Windows answer ISO not found' }}

$vm = Get-VM -Name $vmName -ErrorAction Stop
if ($vm.State -ne 'Off') {{
  throw 'VM must be Off before install bundle reconciliation; automatic stop is forbidden'
}}

$dvdDrives = @(Get-VMDvdDrive -VMName $vmName -ErrorAction SilentlyContinue)
$unknown = @($dvdDrives | Where-Object {{ $_.Path -and $_.Path -ne $windowsIso -and $_.Path -ne $answerIso }})
if ($unknown.Count -gt 0) {{
  throw 'Unmanaged DVD media is attached; refusing silent replacement'
}}

$windowsDvd = $dvdDrives | Where-Object {{ $_.Path -eq $windowsIso }} | Select-Object -First 1
if ($null -eq $windowsDvd) {{
  Add-VMDvdDrive -VMName $vmName -Path $windowsIso | Out-Null
  $changed = $true
}}

$answerDvd = @(Get-VMDvdDrive -VMName $vmName -ErrorAction SilentlyContinue) |
  Where-Object {{ $_.Path -eq $answerIso }} |
  Select-Object -First 1
if ($null -eq $answerDvd) {{
  Add-VMDvdDrive -VMName $vmName -Path $answerIso | Out-Null
  $changed = $true
}}

$windowsDvd = @(Get-VMDvdDrive -VMName $vmName -ErrorAction Stop) |
  Where-Object {{ $_.Path -eq $windowsIso }} |
  Select-Object -First 1
$answerDvd = @(Get-VMDvdDrive -VMName $vmName -ErrorAction Stop) |
  Where-Object {{ $_.Path -eq $answerIso }} |
  Select-Object -First 1
if ($null -eq $windowsDvd -or $null -eq $answerDvd) {{
  throw 'Install bundle readback failed'
}}

Set-VMFirmware -VMName $vmName -FirstBootDevice $windowsDvd

[pscustomobject]@{{
  changed = $changed
  windows_iso_ready = $true
  answer_iso_ready = $true
  windows_iso_path = $windowsDvd.Path
  answer_iso_path = $answerDvd.Path
}}
""".strip()


def reconcile_install_bundle(
    config: WindowsVMConfig,
    windows_iso: Path,
    answer_iso: Path,
) -> InstallBundleObservation:
    payload = run_powershell_json(
        build_reconcile_install_bundle_script(config, windows_iso, answer_iso),
        timeout_seconds=90,
    )
    return InstallBundleObservation(
        windows_iso_ready=bool(payload.get("windows_iso_ready", False)),
        answer_iso_ready=bool(payload.get("answer_iso_ready", False)),
        windows_iso_path=str(payload["windows_iso_path"])
        if payload.get("windows_iso_path")
        else None,
        answer_iso_path=str(payload["answer_iso_path"])
        if payload.get("answer_iso_path")
        else None,
    )
