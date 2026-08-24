from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


_INSTALL_BUNDLE_RESULT_KEYS = frozenset(
    {
        "changed",
        "windows_iso_ready",
        "answer_iso_ready",
        "windows_iso_path",
        "answer_iso_path",
    }
)


def _same_windows_path(left: str, right: str) -> bool:
    return str(PureWindowsPath(left)).casefold() == str(PureWindowsPath(right)).casefold()


@dataclass(frozen=True)
class InstallBundleObservation:
    windows_iso_ready: bool
    answer_iso_ready: bool
    windows_iso_path: str | None = None
    answer_iso_path: str | None = None

    def validate(self) -> None:
        for name in ("windows_iso_ready", "answer_iso_ready"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"install bundle observation must be boolean: {name}")
        for name in ("windows_iso_path", "answer_iso_path"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"install bundle observation {name} must be a string or null")
        if self.windows_iso_ready is not (self.windows_iso_path is not None):
            raise ValueError("Windows ISO readiness/path evidence is inconsistent")
        if self.answer_iso_ready is not (self.answer_iso_path is not None):
            raise ValueError("answer ISO readiness/path evidence is inconsistent")

    @property
    def ready(self) -> bool:
        self.validate()
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
  changed = [bool]$changed
  windows_iso_ready = [bool]$true
  answer_iso_ready = [bool]$true
  windows_iso_path = [string]$windowsDvd.Path
  answer_iso_path = [string]$answerDvd.Path
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
    if set(payload) != _INSTALL_BUNDLE_RESULT_KEYS:
        raise RuntimeError("install bundle reconcile result schema is invalid")
    for key in ("changed", "windows_iso_ready", "answer_iso_ready"):
        if not isinstance(payload[key], bool):
            raise RuntimeError(f"install bundle reconcile {key} must be boolean")
    for key in ("windows_iso_path", "answer_iso_path"):
        value = payload[key]
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"install bundle reconcile {key} must be a non-empty string")

    if payload["windows_iso_ready"] is not True or payload["answer_iso_ready"] is not True:
        raise RuntimeError("install bundle reconcile did not prove both media attachments")
    if not _same_windows_path(payload["windows_iso_path"], str(windows_iso)):
        raise RuntimeError("install bundle reconcile Windows ISO path differs from authority")
    if not _same_windows_path(payload["answer_iso_path"], str(answer_iso)):
        raise RuntimeError("install bundle reconcile answer ISO path differs from authority")

    result = InstallBundleObservation(
        windows_iso_ready=payload["windows_iso_ready"],
        answer_iso_ready=payload["answer_iso_ready"],
        windows_iso_path=payload["windows_iso_path"],
        answer_iso_path=payload["answer_iso_path"],
    )
    result.validate()
    return result
