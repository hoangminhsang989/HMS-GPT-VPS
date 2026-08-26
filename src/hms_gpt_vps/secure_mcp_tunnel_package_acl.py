from __future__ import annotations

from pathlib import PureWindowsPath

from .bridge_service_identity import require_hms_bridge_service_sid
from .powershell import ps_literal, run_powershell_json
from .secure_mcp_tunnel_package import (
    EXPECTED_RUNTIME_ARCHIVE_FILES,
    TunnelRuntimePackageConfig,
    TunnelRuntimePackageError,
)

_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_KEYS = frozenset({"ready","changed","package_root","install_root","manifest_path","service_sid","directory_acls_exact","file_acls_exact","exact_entries","reparse_point_found"})


def build_tunnel_package_acl_script(config: TunnelRuntimePackageConfig, *, service_sid: str, reconcile: bool) -> str:
    config.validate(); require_hms_bridge_service_sid(service_sid)
    root = ps_literal(str(PureWindowsPath(str(config.package_root))))
    install = ps_literal(str(PureWindowsPath(str(config.install_root))))
    manifest = ps_literal(str(PureWindowsPath(str(config.manifest_path))))
    sid = ps_literal(service_sid)
    names = ",".join(ps_literal(name) for name in sorted(EXPECTED_RUNTIME_ARCHIVE_FILES))
    reconcile_text = "$true" if reconcile else "$false"
    return f"""
$ErrorActionPreference='Stop'
$packageRoot=[IO.Path]::GetFullPath({root})
$installRoot=[IO.Path]::GetFullPath({install})
$manifestPath=[IO.Path]::GetFullPath({manifest})
$serviceSidText={sid}
$expectedFiles=@({names})
$reconcile={reconcile_text}
$systemSidText='{_SYSTEM_SID}'
$adminsSidText='{_ADMINISTRATORS_SID}'
$changed=$false
function Assert-NoReparse([string]$path) {{
  $full=[IO.Path]::GetFullPath($path); $drive=[IO.Path]::GetPathRoot($full); $current=$drive
  foreach($part in $full.Substring($drive.Length).Split([IO.Path]::DirectorySeparatorChar,[StringSplitOptions]::RemoveEmptyEntries)) {{
    $current=[IO.Path]::Combine($current,$part)
    if(Test-Path -LiteralPath $current) {{
      $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'Tunnel package authority traverses a reparse point' }}
    }}
  }}
}}
$systemSid=[Security.Principal.SecurityIdentifier]::new($systemSidText)
$adminsSid=[Security.Principal.SecurityIdentifier]::new($adminsSidText)
$serviceSid=[Security.Principal.SecurityIdentifier]::new($serviceSidText)
$serviceRights=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
function New-Rule($sid,$rights,[bool]$directory) {{
  if($directory) {{
    return [Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
  }}
  return [Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,[Security.AccessControl.AccessControlType]::Allow)
}}
function Test-ExactAcl($acl,[bool]$directory) {{
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $adminsSidText -or -not $acl.AreAccessRulesProtected) {{ return $false }}
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); if($rules.Count -ne 3) {{ return $false }}
  $expected=@{{$systemSidText=[Security.AccessControl.FileSystemRights]::FullControl;$adminsSidText=[Security.AccessControl.FileSystemRights]::FullControl;$serviceSidText=$serviceRights}}
  foreach($rule in $rules) {{
    if($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or -not $expected.ContainsKey($rule.IdentityReference.Value)) {{ return $false }}
    if([int64]$rule.FileSystemRights -ne [int64]$expected[$rule.IdentityReference.Value]) {{ return $false }}
    if($directory) {{
      $wanted=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
      if($rule.InheritanceFlags -ne $wanted -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {{ return $false }}
    }} elseif($rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {{ return $false }}
  }}
  return $true
}}
function Set-ExactAcl([string]$path,[bool]$directory) {{
  if($directory) {{$acl=[Security.AccessControl.DirectorySecurity]::new()}} else {{$acl=[Security.AccessControl.FileSecurity]::new()}}
  $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($adminsSid)
  $acl.AddAccessRule((New-Rule $systemSid ([Security.AccessControl.FileSystemRights]::FullControl) $directory))
  $acl.AddAccessRule((New-Rule $adminsSid ([Security.AccessControl.FileSystemRights]::FullControl) $directory))
  $acl.AddAccessRule((New-Rule $serviceSid $serviceRights $directory)); Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
}}
foreach($path in @($packageRoot,$installRoot,$manifestPath)) {{ Assert-NoReparse $path }}
if(-not(Test-Path $packageRoot -PathType Container) -or -not(Test-Path $installRoot -PathType Container) -or -not(Test-Path $manifestPath -PathType Leaf)) {{ throw 'Tunnel package authority is incomplete' }}
$roots=@(Get-ChildItem $packageRoot -Force); if($roots.Count -ne 2) {{ throw 'Tunnel package root exact entries differ' }}
$installed=@(Get-ChildItem $installRoot -Force); if($installed.Count -ne $expectedFiles.Count) {{ throw 'Tunnel package installed file count differs' }}
foreach($entry in $installed) {{ if($entry.PSIsContainer -or $expectedFiles -notcontains $entry.Name) {{ throw 'Tunnel package contains an unexpected entry' }}; Assert-NoReparse $entry.FullName }}
foreach($name in $expectedFiles) {{ if(-not(Test-Path (Join-Path $installRoot $name) -PathType Leaf)) {{ throw 'Tunnel package expected file is missing' }} }}
$dirs=@($packageRoot,$installRoot); $files=@($manifestPath)+@($installed|%{{$_.FullName}})
foreach($path in $dirs) {{ if(-not(Test-ExactAcl (Get-Acl $path) $true)) {{ if(-not $reconcile) {{throw 'Tunnel package directory ACL differs'}}; Set-ExactAcl $path $true; $changed=$true }} }}
foreach($path in $files) {{ if(-not(Test-ExactAcl (Get-Acl $path) $false)) {{ if(-not $reconcile) {{throw 'Tunnel package file ACL differs'}}; Set-ExactAcl $path $false; $changed=$true }} }}
$dirExact=$true; foreach($path in $dirs) {{if(-not(Test-ExactAcl (Get-Acl $path) $true)){{$dirExact=$false}}}}
$fileExact=$true; foreach($path in $files) {{if(-not(Test-ExactAcl (Get-Acl $path) $false)){{$fileExact=$false}}}}
[pscustomobject]@{{ready=[bool]($dirExact-and$fileExact);changed=[bool]$changed;package_root=$packageRoot;install_root=$installRoot;manifest_path=$manifestPath;service_sid=$serviceSidText;directory_acls_exact=[bool]$dirExact;file_acls_exact=[bool]$fileExact;exact_entries=$true;reparse_point_found=$false}}
""".strip()


def _validate(result: dict[str, object], config: TunnelRuntimePackageConfig, sid: str, *, reconcile: bool) -> dict[str, object]:
    if frozenset(result) != _KEYS: raise TunnelRuntimePackageError("tunnel package ACL evidence schema differs")
    for key, expected in {"package_root":str(PureWindowsPath(str(config.package_root))),"install_root":str(PureWindowsPath(str(config.install_root))),"manifest_path":str(PureWindowsPath(str(config.manifest_path)))}.items():
        value=result.get(key)
        if not isinstance(value,str) or value.casefold()!=expected.casefold(): raise TunnelRuntimePackageError(f"tunnel package ACL path evidence differs: {key}")
    if result.get("service_sid") != sid: raise TunnelRuntimePackageError("tunnel package ACL service SID differs")
    for key in ("ready","directory_acls_exact","file_acls_exact","exact_entries"):
        if result.get(key) is not True: raise TunnelRuntimePackageError(f"tunnel package ACL evidence differs: {key}")
    if result.get("reparse_point_found") is not False or not isinstance(result.get("changed"),bool): raise TunnelRuntimePackageError("tunnel package ACL evidence is invalid")
    if not reconcile and result.get("changed") is not False: raise TunnelRuntimePackageError("runtime tunnel package proof must not reconcile ACLs")
    return dict(result)


def reconcile_tunnel_package_acls(config: TunnelRuntimePackageConfig, *, service_sid: str) -> dict[str, object]:
    return _validate(run_powershell_json(build_tunnel_package_acl_script(config,service_sid=service_sid,reconcile=True),timeout_seconds=90),config,service_sid,reconcile=True)


def prove_tunnel_package_acls(config: TunnelRuntimePackageConfig, *, service_sid: str) -> dict[str, object]:
    return _validate(run_powershell_json(build_tunnel_package_acl_script(config,service_sid=service_sid,reconcile=False),timeout_seconds=60),config,service_sid,reconcile=False)
