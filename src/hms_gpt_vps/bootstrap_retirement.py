from __future__ import annotations

from pathlib import Path

from .powershell import ps_literal, run_powershell_json
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


def _validate_bootstrap_username(username: str) -> None:
    if not username.strip():
        raise ValueError("bootstrap username is required")
    if len(username) > 20:
        raise ValueError("bootstrap username is too long")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    if any(char not in allowed for char in username):
        raise ValueError("bootstrap username contains unsupported characters")


def build_retire_bootstrap_guest_script(username: str) -> str:
    """Build the final credentialed guest action for the bootstrap account.

    The account is disabled, not deleted. AutoLogon password residue is removed,
    and only cached unattend files that actually mention the managed bootstrap
    username are deleted. The caller must durably record the successful result
    before clearing host-side DPAPI state because this action invalidates the
    credential used by PowerShell Direct.
    """
    _validate_bootstrap_username(username)
    user = ps_literal(username)
    return f"""
$ErrorActionPreference = 'Stop'
$bootstrapUser = {user}

$winlogon = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
if (Test-Path $winlogon) {{
  $props = Get-ItemProperty -Path $winlogon -ErrorAction Stop
  Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value '0' -Type String -ErrorAction Stop
  Remove-ItemProperty -Path $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
  if ($props.DefaultUserName -eq $bootstrapUser) {{
    Remove-ItemProperty -Path $winlogon -Name DefaultUserName -ErrorAction SilentlyContinue
  }}
}}

$removedUnattend = @()
$candidates = @(
  'C:\\Windows\\Panther\\unattend.xml',
  'C:\\Windows\\Panther\\Unattend\\Unattend.xml',
  'C:\\Windows\\System32\\Sysprep\\unattend.xml'
)
foreach ($candidate in $candidates) {{
  if (Test-Path -LiteralPath $candidate -PathType Leaf) {{
    $text = Get-Content -LiteralPath $candidate -Raw -ErrorAction Stop
    if ($text -match [regex]::Escape($bootstrapUser)) {{
      Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop
      $removedUnattend += $candidate
    }}
  }}
}}

$localUser = Get-LocalUser -Name $bootstrapUser -ErrorAction SilentlyContinue
if ($null -ne $localUser -and $localUser.Enabled) {{
  Disable-LocalUser -Name $bootstrapUser -ErrorAction Stop
}}
$localUser = Get-LocalUser -Name $bootstrapUser -ErrorAction SilentlyContinue
$userDisabled = $null -eq $localUser -or -not $localUser.Enabled

$autoLogonDisabled = $true
$defaultPasswordAbsent = $true
if (Test-Path $winlogon) {{
  $after = Get-ItemProperty -Path $winlogon -ErrorAction Stop
  $autoLogonDisabled = $after.AutoAdminLogon -ne '1'
  $defaultPasswordAbsent = $null -eq $after.PSObject.Properties['DefaultPassword']
}}

[pscustomobject]@{{
  retired = [bool]($userDisabled -and $autoLogonDisabled -and $defaultPasswordAbsent)
  bootstrap_user = $bootstrapUser
  account_disabled = [bool]$userDisabled
  autologon_disabled = [bool]$autoLogonDisabled
  default_password_absent = [bool]$defaultPasswordAbsent
  removed_unattend_count = $removedUnattend.Count
}}
""".strip()


def retire_bootstrap_guest(
    vm_name: str,
    credential: PowerShellDirectCredential,
    username: str,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_retire_bootstrap_guest_script(username),
        timeout_seconds=timeout_seconds,
    )
    if not bool(result.get("retired", False)):
        raise RuntimeError("bootstrap guest retirement postcondition failed")
    return result


def build_detach_answer_iso_script(vm_name: str, answer_iso: Path) -> str:
    if not vm_name.strip():
        raise ValueError("VM name is required")
    vm = ps_literal(vm_name)
    iso = ps_literal(answer_iso.expanduser().resolve())
    return f"""
$ErrorActionPreference = 'Stop'
$vmName = {vm}
$answerIso = {iso}
$matches = @(Get-VMDvdDrive -VMName $vmName -ErrorAction Stop | Where-Object {{ $_.Path -eq $answerIso }})
if ($matches.Count -gt 1) {{ throw 'multiple DVD drives reference the managed answer ISO' }}
if ($matches.Count -eq 1) {{
  Set-VMDvdDrive -VMDvdDrive $matches[0] -Path $null -ErrorAction Stop
}}
$remaining = @(Get-VMDvdDrive -VMName $vmName -ErrorAction Stop | Where-Object {{ $_.Path -eq $answerIso }})
[pscustomobject]@{{
  detached = [bool]($remaining.Count -eq 0)
  answer_iso = $answerIso
}}
""".strip()


def detach_answer_iso(vm_name: str, answer_iso: Path) -> dict[str, object]:
    result = run_powershell_json(
        build_detach_answer_iso_script(vm_name, answer_iso),
        timeout_seconds=90,
    )
    if not bool(result.get("detached", False)):
        raise RuntimeError("managed answer ISO detach postcondition failed")
    return result
