from __future__ import annotations

from pathlib import Path

from .hyperv_vm import vhd_path_for
from .powershell import ps_literal, run_powershell_json
from .windows_image import sha256_file
from .windows_provisioner import WindowsVMConfig


def _normalize_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{label} must contain 64 hex characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{label} must be hexadecimal") from exc
    return value.lower()


def build_start_unattended_install_script(
    config: WindowsVMConfig,
    windows_iso: Path,
    answer_iso: Path,
    *,
    expected_windows_sha256: str | None = None,
    expected_answer_sha256: str | None = None,
) -> str:
    """Start Windows Setup only after all destructive-target invariants hold.

    The unattend answer uses WillWipeDisk=true, so this gate verifies that the
    VM owns exactly one managed VHDX and that both intended ISO files plus the
    Windows 11 security baseline are present before starting the VM.

    When expected hashes are supplied, both ISO files are opened read-only with
    FileShare.Read, which denies writers/deleters while still allowing Hyper-V
    to open the same media for reading. The SHA-256 values are computed from
    those exact open handles and the handles remain held until Start-VM has
    reached Running, closing the verify-to-use replacement window.
    """
    config.validate()
    if windows_iso.suffix.lower() != ".iso" or answer_iso.suffix.lower() != ".iso":
        raise ValueError("Windows and answer media must both be ISO files")
    windows_hash = (
        _normalize_sha256(expected_windows_sha256, "Windows ISO SHA-256")
        if expected_windows_sha256 is not None
        else None
    )
    answer_hash = (
        _normalize_sha256(expected_answer_sha256, "answer ISO SHA-256")
        if expected_answer_sha256 is not None
        else None
    )

    vm_name = ps_literal(config.name)
    vhd = ps_literal(vhd_path_for(config))
    product = ps_literal(windows_iso)
    answer = ps_literal(answer_iso)
    expected_windows_hash = ps_literal(windows_hash) if windows_hash is not None else "$null"
    expected_answer_hash = ps_literal(answer_hash) if answer_hash is not None else "$null"

    return f"""
$ErrorActionPreference = 'Stop'
$vmName = {vm_name}
$managedVhd = {vhd}
$windowsIso = {product}
$answerIso = {answer}
$expectedWindowsHash = {expected_windows_hash}
$expectedAnswerHash = {expected_answer_hash}

function Get-HmsLockedStreamSha256([System.IO.Stream]$Stream) {{
  $Stream.Position = 0
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {{
    $digest = $sha.ComputeHash($Stream)
  }} finally {{
    $sha.Dispose()
  }}
  $Stream.Position = 0
  return ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
}}

$windowsHandle = $null
$answerHandle = $null
try {{
  $windowsHandle = [System.IO.File]::Open(
    $windowsIso,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  $answerHandle = [System.IO.File]::Open(
    $answerIso,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )

  $lockedWindowsHash = Get-HmsLockedStreamSha256 $windowsHandle
  $lockedAnswerHash = Get-HmsLockedStreamSha256 $answerHandle
  if ($null -ne $expectedWindowsHash -and $lockedWindowsHash -ne $expectedWindowsHash) {{
    throw 'Destructive install gate: Windows ISO changed before locked VM start'
  }}
  if ($null -ne $expectedAnswerHash -and $lockedAnswerHash -ne $expectedAnswerHash) {{
    throw 'Destructive install gate: answer ISO changed before locked VM start'
  }}

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
    changed = [bool]$true
    vm_id = [string]$started.Id.Guid
    vm_state = [string]$started.State.ToString()
    managed_vhd = [string]$observedVhd
    windows_iso = [string]$productDvd.Path
    answer_iso = [string]$answerDvd.Path
    windows_iso_sha256 = [string]$lockedWindowsHash
    answer_iso_sha256 = [string]$lockedAnswerHash
    media_lock_held_until_running = [bool]$true
  }}
}} finally {{
  if ($null -ne $answerHandle) {{ $answerHandle.Dispose() }}
  if ($null -ne $windowsHandle) {{ $windowsHandle.Dispose() }}
}}
""".strip()


def start_unattended_install(
    config: WindowsVMConfig,
    windows_iso: Path,
    answer_iso: Path,
    *,
    expected_windows_sha256: str | None = None,
    expected_answer_sha256: str | None = None,
) -> dict[str, object]:
    # Even callers without a pre-pinned digest get a host-side snapshot digest
    # before the PowerShell process opens and locks the files. If the path is
    # replaced between these operations, the locked-handle hash comparison
    # fails closed. Production passes the durable answer-media digest directly.
    windows_hash = expected_windows_sha256 or sha256_file(windows_iso)
    answer_hash = expected_answer_sha256 or sha256_file(answer_iso)
    windows_hash = _normalize_sha256(windows_hash, "Windows ISO SHA-256")
    answer_hash = _normalize_sha256(answer_hash, "answer ISO SHA-256")

    result = run_powershell_json(
        build_start_unattended_install_script(
            config,
            windows_iso,
            answer_iso,
            expected_windows_sha256=windows_hash,
            expected_answer_sha256=answer_hash,
        ),
        timeout_seconds=90,
    )
    expected_keys = {
        "changed",
        "vm_id",
        "vm_state",
        "managed_vhd",
        "windows_iso",
        "answer_iso",
        "windows_iso_sha256",
        "answer_iso_sha256",
        "media_lock_held_until_running",
    }
    if set(result) != expected_keys:
        raise RuntimeError("unattended install start result schema is invalid")
    if result["changed"] is not True or result["media_lock_held_until_running"] is not True:
        raise RuntimeError("unattended install start did not prove locked media handoff")
    if result["vm_state"] != "Running":
        raise RuntimeError("unattended install start did not prove Running state")
    if result["windows_iso_sha256"] != windows_hash:
        raise RuntimeError("unattended install Windows ISO hash differs from authority")
    if result["answer_iso_sha256"] != answer_hash:
        raise RuntimeError("unattended install answer ISO hash differs from authority")
    return result
