from __future__ import annotations

from pathlib import Path
from typing import Mapping

from .r002f_sealed_execution_manifest import R002FSealedExecutionTreeError


def build_exact_readonly_acl_powershell(root: Path, *, reconcile: bool) -> str:
    if not isinstance(root, Path):
        raise TypeError("root must be pathlib.Path")
    escaped = str(root.expanduser().absolute()).replace("'", "''")
    reconcile_text = "$true" if reconcile else "$false"
    return rf"""
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath('{escaped}')
$reconcile={reconcile_text}
$system='S-1-5-18'
$admins='S-1-5-32-544'
function Assert-NoReparse([string]$path) {{
  $full=[IO.Path]::GetFullPath($path); $drive=[IO.Path]::GetPathRoot($full); $current=$drive
  foreach($part in $full.Substring($drive.Length).Split([IO.Path]::DirectorySeparatorChar,[StringSplitOptions]::RemoveEmptyEntries)) {{
    $current=[IO.Path]::Combine($current,$part)
    if(Test-Path -LiteralPath $current) {{
      $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'sealed execution authority traverses reparse point' }}
    }}
  }}
}}
function Expected-Rights([bool]$directory) {{
  return [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
}}
function Test-ExactAcl([string]$path,[bool]$directory) {{
  $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $admins -or -not $acl.AreAccessRulesProtected) {{ return $false }}
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if($rules.Count -ne 2) {{ return $false }}
  $wanted=[int64](Expected-Rights $directory)
  foreach($rule in $rules) {{
    if($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {{ return $false }}
    if($rule.IdentityReference.Value -ne $system -and $rule.IdentityReference.Value -ne $admins) {{ return $false }}
    if([int64]$rule.FileSystemRights -ne $wanted) {{ return $false }}
    if($rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {{ return $false }}
  }}
  return $true
}}
function Set-ExactAcl([string]$path,[bool]$directory) {{
  $owner=[Security.Principal.SecurityIdentifier]::new($admins)
  if($directory) {{ $acl=[Security.AccessControl.DirectorySecurity]::new() }} else {{ $acl=[Security.AccessControl.FileSecurity]::new() }}
  $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($owner)
  $rights=Expected-Rights $directory
  foreach($sidText in @($system,$admins)) {{
    $sid=[Security.Principal.SecurityIdentifier]::new($sidText)
    $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,[Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
  }}
  Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
}}
Assert-NoReparse $root
if(-not(Test-Path -LiteralPath $root -PathType Container)) {{ throw 'sealed execution root is missing' }}
$entries=@(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
foreach($entry in $entries) {{ Assert-NoReparse $entry.FullName }}
$all=@([pscustomobject]@{{Path=$root;Directory=$true}})
foreach($entry in $entries) {{ $all += [pscustomobject]@{{Path=$entry.FullName;Directory=[bool]$entry.PSIsContainer}} }}
$changed=$false
$reconcileItems=@($all | Sort-Object {{ $_.Path.Length }} -Descending)
foreach($item in $reconcileItems) {{
  if(-not(Test-ExactAcl $item.Path $item.Directory)) {{
    if(-not $reconcile) {{ throw 'sealed execution ACL differs' }}
    Set-ExactAcl $item.Path $item.Directory
    $changed=$true
  }}
}}
$exact=$true
foreach($item in $all) {{ if(-not(Test-ExactAcl $item.Path $item.Directory)) {{ $exact=$false }} }}
[pscustomobject]@{{ready=[bool]$exact;changed=[bool]$changed;root=$root;entry_count=[int]$entries.Count;directory_acls_exact=[bool]$exact;file_acls_exact=[bool]$exact;reparse_point_found=$false}}
""".strip()


def validate_acl_evidence(
    evidence: Mapping[str, object],
    *,
    root: Path,
    expected_entry_count: int,
    reconcile: bool,
) -> dict[str, object]:
    required = frozenset(
        {
            "ready",
            "changed",
            "root",
            "entry_count",
            "directory_acls_exact",
            "file_acls_exact",
            "reparse_point_found",
        }
    )
    if frozenset(evidence) != required:
        raise R002FSealedExecutionTreeError(
            "sealed execution ACL evidence schema differs"
        )
    if evidence.get("ready") is not True:
        raise R002FSealedExecutionTreeError(
            "sealed execution ACL evidence is not ready"
        )
    changed = evidence.get("changed")
    if not isinstance(changed, bool):
        raise R002FSealedExecutionTreeError(
            "sealed execution ACL changed flag is invalid"
        )
    if not reconcile and changed is not False:
        raise R002FSealedExecutionTreeError(
            "runtime sealed execution ACL proof must not reconcile"
        )
    observed_root = evidence.get("root")
    if (
        not isinstance(observed_root, str)
        or Path(observed_root).expanduser().absolute()
        != root.expanduser().absolute()
    ):
        raise R002FSealedExecutionTreeError(
            "sealed execution ACL root evidence differs"
        )
    count = evidence.get("entry_count")
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or count != expected_entry_count
    ):
        raise R002FSealedExecutionTreeError(
            "sealed execution ACL entry count differs"
        )
    if (
        evidence.get("directory_acls_exact") is not True
        or evidence.get("file_acls_exact") is not True
        or evidence.get("reparse_point_found") is not False
    ):
        raise R002FSealedExecutionTreeError(
            "sealed execution ACL evidence differs"
        )
    return dict(evidence)
