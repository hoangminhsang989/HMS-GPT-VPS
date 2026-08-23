from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


@dataclass(frozen=True)
class InstallBundleState:
    windows_iso_ready: bool
    answer_iso_ready: bool
    first_boot_is_windows_iso: bool

    @property
    def ready(self) -> bool:
        return (
            self.windows_iso_ready
            and self.answer_iso_ready
            and self.first_boot_is_windows_iso
        )


def build_observe_install_bundle_script(
    config: WindowsVMConfig,
    windows_iso: Path,
    answer_iso: Path,
) -> str:
    config.validate()
    vm_name = ps_literal(config.name)
    product = ps_literal(windows_iso)
    answer = ps_literal(answer_iso)
    return f"""
$ErrorActionPreference = 'Stop'
$vmName = {vm_name}
$windowsIso = {product}
$answerIso = {answer}
$dvds = @(Get-VMDvdDrive -VMName $vmName -ErrorAction SilentlyContinue)
$productDvd = $dvds | Where-Object {{ $_.Path -eq $windowsIso }} | Select-Object -First 1
$answerDvd = $dvds | Where-Object {{ $_.Path -eq $answerIso }} | Select-Object -First 1
$firmware = Get-VMFirmware -VMName $vmName -ErrorAction SilentlyContinue
$firstBoot = $null
if ($null -ne $firmware -and $firmware.BootOrder.Count -gt 0) {{
  $firstBoot = $firmware.BootOrder[0]
}}
$firstBootMatches = $false
if ($null -ne $productDvd -and $null -ne $firstBoot) {{
  $firstBootMatches = (
    $firstBoot.Device -eq 'Cd' -and
    $firstBoot.ControllerNumber -eq $productDvd.ControllerNumber -and
    $firstBoot.ControllerLocation -eq $productDvd.ControllerLocation
  )
}}
[pscustomobject]@{{
  windows_iso_ready = [bool]($null -ne $productDvd)
  answer_iso_ready = [bool]($null -ne $answerDvd)
  first_boot_is_windows_iso = [bool]$firstBootMatches
}}
""".strip()


def observe_install_bundle(
    config: WindowsVMConfig,
    windows_iso: Path,
    answer_iso: Path,
) -> InstallBundleState:
    payload = run_powershell_json(
        build_observe_install_bundle_script(config, windows_iso, answer_iso),
        timeout_seconds=60,
    )
    return InstallBundleState(
        windows_iso_ready=bool(payload.get("windows_iso_ready", False)),
        answer_iso_ready=bool(payload.get("answer_iso_ready", False)),
        first_boot_is_windows_iso=bool(payload.get("first_boot_is_windows_iso", False)),
    )
