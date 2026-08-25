from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath

from .powershell import ps_literal, run_powershell_json
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json

_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_RETIRE_RESULT_KEYS = frozenset({
    "retired", "bootstrap_user", "account_disabled", "autologon_disabled",
    "default_password_absent", "removed_unattend_count",
})
_DETACH_RESULT_KEYS = frozenset({"detached", "answer_iso"})


def _validate_bootstrap_username(username: str) -> None:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("bootstrap username is required")
    if len(username) > 20:
        raise ValueError("bootstrap username is too long")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    if any(char not in allowed for char in username):
        raise ValueError("bootstrap username contains unsupported characters")


def _validate_timeout_seconds(timeout_seconds: int) -> None:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
        raise ValueError("timeout_seconds must be an integer")
    if not 1 <= timeout_seconds <= 600:
        raise ValueError("timeout_seconds must be between 1 and 600")


def _lexical_absolute(path: Path) -> Path:
    return path.expanduser().absolute()


def _path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = _lexical_absolute(path)
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            return True
        try:
            stat_result = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = int(getattr(stat_result, "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    return False


def _require_answer_iso_authority(answer_iso: Path) -> Path:
    authority = _lexical_absolute(answer_iso)
    if authority.suffix.lower() != ".iso":
        raise ValueError("managed answer media must use .iso extension")
    if _path_chain_has_redirect(authority):
        raise ValueError("managed answer ISO path must not traverse a link or reparse point")
    return authority


def _same_windows_path(left: str, right: Path) -> bool:
    return str(PureWindowsPath(left)).casefold() == str(
        PureWindowsPath(str(_lexical_absolute(right)))
    ).casefold()


def _validate_retirement_result(result: object, *, expected_username: str) -> dict[str, object]:
    if not isinstance(result, dict):
        raise RuntimeError("bootstrap guest retirement result must be an object")
    if frozenset(result) != _RETIRE_RESULT_KEYS:
        raise RuntimeError("bootstrap guest retirement result schema is invalid")
    if result["retired"] is not True:
        raise RuntimeError("bootstrap guest retirement postcondition failed")
    if result["bootstrap_user"] != expected_username:
        raise RuntimeError("bootstrap guest retirement user differs from authority")
    for key in ("account_disabled", "autologon_disabled", "default_password_absent"):
        if result[key] is not True:
            raise RuntimeError(f"bootstrap guest retirement did not prove exact {key}")
    removed_count = result["removed_unattend_count"]
    if isinstance(removed_count, bool) or not isinstance(removed_count, int) or not 0 <= removed_count <= 3:
        raise RuntimeError("bootstrap guest retirement removed_unattend_count is invalid")
    return result


def _validate_detach_result(result: object, *, expected_answer_iso: Path) -> dict[str, object]:
    if not isinstance(result, dict):
        raise RuntimeError("managed answer ISO detach result must be an object")
    if frozenset(result) != _DETACH_RESULT_KEYS:
        raise RuntimeError("managed answer ISO detach result schema is invalid")
    if result["detached"] is not True:
        raise RuntimeError("managed answer ISO detach postcondition failed")
    observed_answer = result["answer_iso"]
    if not isinstance(observed_answer, str) or not _same_windows_path(observed_answer, expected_answer_iso):
        raise RuntimeError("managed answer ISO detach path differs from authority")
    return result


def build_retire_bootstrap_guest_script(username: str) -> str:
    """Build the final credentialed guest action for the bootstrap account."""
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
    if not isinstance(vm_name, str) or not vm_name.strip():
        raise ValueError("VM name is required")
    credential.validate()
    _validate_bootstrap_username(username)
    _validate_timeout_seconds(timeout_seconds)
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_retire_bootstrap_guest_script(username),
        timeout_seconds=timeout_seconds,
    )
    return _validate_retirement_result(result, expected_username=username)


def build_detach_answer_iso_script(vm_name: str, answer_iso: Path) -> str:
    if not isinstance(vm_name, str) or not vm_name.strip():
        raise ValueError("VM name is required")
    answer_authority = _require_answer_iso_authority(answer_iso)
    vm = ps_literal(vm_name)
    iso = ps_literal(answer_authority)
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


def detach_answer_iso(
    vm_name: str,
    answer_iso: Path,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    _validate_timeout_seconds(timeout_seconds)
    answer_authority = _require_answer_iso_authority(answer_iso)
    result = run_powershell_json(
        build_detach_answer_iso_script(vm_name, answer_authority),
        timeout_seconds=timeout_seconds,
    )
    return _validate_detach_result(result, expected_answer_iso=answer_authority)
