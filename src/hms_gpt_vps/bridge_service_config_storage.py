from __future__ import annotations

import hashlib
from pathlib import Path, PureWindowsPath

from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    require_hms_bridge_service_sid,
)
from .powershell import ps_literal, run_powershell_json
from .qualification_file_authority import read_file_pinned


DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\bridge-runtime.json"
)
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_RESULT_KEYS = frozenset(
    {
        "ready",
        "changed",
        "root",
        "config_path",
        "config_sha256",
        "root_owner_sid",
        "config_owner_sid",
        "service_sid",
        "root_acl_exact",
        "config_acl_exact",
        "root_reparse_point",
        "config_reparse_point",
    }
)


class BridgeServiceConfigStorageError(RuntimeError):
    pass


def _fixed_config_path(path: Path) -> str:
    if not isinstance(path, Path):
        raise TypeError("Bridge runtime config path must be pathlib.Path")
    observed = str(PureWindowsPath(str(path)))
    expected = str(PureWindowsPath(str(DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH)))
    if observed.casefold() != expected.casefold():
        raise BridgeServiceConfigStorageError(
            "Bridge runtime config path differs from fixed ProgramData authority"
        )
    return expected


def build_bridge_service_config_storage_script(
    path: Path = DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
    *,
    reconcile: bool,
) -> str:
    config_path = ps_literal(_fixed_config_path(path))
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    system_sid = ps_literal(_SYSTEM_SID)
    administrators_sid = ps_literal(_ADMINISTRATORS_SID)
    reconcile_literal = "$true" if reconcile else "$false"

    return f"""
$ErrorActionPreference = 'Stop'
$configPath = [System.IO.Path]::GetFullPath({config_path})
$root = [System.IO.Path]::GetDirectoryName($configPath)
$serviceAccount = {service_account}
$systemSidText = {system_sid}
$administratorsSidText = {administrators_sid}
$reconcile = {reconcile_literal}

function Assert-NoReparseChain([string]$path) {{
  $full = [System.IO.Path]::GetFullPath($path)
  $driveRoot = [System.IO.Path]::GetPathRoot($full)
  $relative = $full.Substring($driveRoot.Length)
  $current = $driveRoot
  foreach ($segment in @($relative.Split([System.IO.Path]::DirectorySeparatorChar, [System.StringSplitOptions]::RemoveEmptyEntries))) {{
    $current = [System.IO.Path]::Combine($current, $segment)
    if (Test-Path -LiteralPath $current) {{
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
        throw 'HMSBridge runtime-config authority traverses a reparse point'
      }}
    }}
  }}
}}

function New-Sid([string]$text) {{
  return [System.Security.Principal.SecurityIdentifier]::new($text)
}}

function New-Rule(
  [System.Security.Principal.SecurityIdentifier]$sid,
  [System.Security.AccessControl.FileSystemRights]$rights
) {{
  return [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    $rights,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}}

function Test-ExactAcl(
  [System.Security.AccessControl.FileSystemSecurity]$acl,
  [hashtable]$expected,
  [string]$ownerSidText
) {{
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne $ownerSidText) {{ return $false }}
  if (-not $acl.AreAccessRulesProtected) {{ return $false }}
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne $expected.Count) {{ return $false }}
  foreach ($rule in $rules) {{
    if ($rule.IsInherited) {{ return $false }}
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {{
      return $false
    }}
    if ($rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None) {{
      return $false
    }}
    if ($rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {{
      return $false
    }}
    $sid = $rule.IdentityReference.Value
    if (-not $expected.ContainsKey($sid)) {{ return $false }}
    if ([int64]$rule.FileSystemRights -ne [int64]$expected[$sid]) {{ return $false }}
  }}
  return $true
}}

Assert-NoReparseChain $root
Assert-NoReparseChain $configPath
if (-not (Test-Path -LiteralPath $root -PathType Container)) {{
  throw 'HMSBridge runtime-config root is missing'
}}
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {{
  throw 'HMSBridge runtime config is missing'
}}
$rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
$configItem = Get-Item -LiteralPath $configPath -Force -ErrorAction Stop
if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMSBridge runtime-config root is a reparse point'
}}
if (($configItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMSBridge runtime config is a reparse point'
}}

$serviceSid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate(
  [System.Security.Principal.SecurityIdentifier]
).Value
if (-not $serviceSid.StartsWith('S-1-5-80-')) {{
  throw 'HMSBridge virtual account did not resolve to a service SID'
}}
$systemSid = New-Sid $systemSidText
$administratorsSid = New-Sid $administratorsSidText
$readerSid = New-Sid $serviceSid
$expectedRoot = @{{}}
$expectedRoot[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$expectedRoot[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$expectedRoot[$serviceSid] = (
  [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
  [System.Security.AccessControl.FileSystemRights]::Synchronize
)
$expectedFile = @{{}}
$expectedFile[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$expectedFile[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$expectedFile[$serviceSid] = (
  [System.Security.AccessControl.FileSystemRights]::Read -bor
  [System.Security.AccessControl.FileSystemRights]::Synchronize
)

$beforeSha = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
$changed = $false
$rootAcl = Get-Acl -LiteralPath $root -ErrorAction Stop
$configAcl = Get-Acl -LiteralPath $configPath -ErrorAction Stop
$rootExact = Test-ExactAcl $rootAcl $expectedRoot $administratorsSidText
$configExact = Test-ExactAcl $configAcl $expectedFile $administratorsSidText

if ((-not $rootExact -or -not $configExact) -and -not $reconcile) {{
  throw 'HMSBridge runtime-config ACL differs from exact service authority'
}}
if ($reconcile -and -not $rootExact) {{
  $newRootAcl = [System.Security.AccessControl.DirectorySecurity]::new()
  $newRootAcl.SetAccessRuleProtection($true, $false)
  $newRootAcl.SetOwner($administratorsSid)
  $newRootAcl.AddAccessRule((New-Rule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newRootAcl.AddAccessRule((New-Rule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newRootAcl.AddAccessRule((New-Rule $readerSid ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)))
  Set-Acl -LiteralPath $root -AclObject $newRootAcl -ErrorAction Stop
  $changed = $true
}}
if ($reconcile -and -not $configExact) {{
  $newConfigAcl = [System.Security.AccessControl.FileSecurity]::new()
  $newConfigAcl.SetAccessRuleProtection($true, $false)
  $newConfigAcl.SetOwner($administratorsSid)
  $newConfigAcl.AddAccessRule((New-Rule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newConfigAcl.AddAccessRule((New-Rule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newConfigAcl.AddAccessRule((New-Rule $readerSid ([System.Security.AccessControl.FileSystemRights]::Read)))
  Set-Acl -LiteralPath $configPath -AclObject $newConfigAcl -ErrorAction Stop
  $changed = $true
}}

Assert-NoReparseChain $root
Assert-NoReparseChain $configPath
$rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
$configItem = Get-Item -LiteralPath $configPath -Force -ErrorAction Stop
$afterSha = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($afterSha -ne $beforeSha) {{
  throw 'HMSBridge runtime config content changed during ACL authority check'
}}
$rootAcl = Get-Acl -LiteralPath $root -ErrorAction Stop
$configAcl = Get-Acl -LiteralPath $configPath -ErrorAction Stop
$rootExact = Test-ExactAcl $rootAcl $expectedRoot $administratorsSidText
$configExact = Test-ExactAcl $configAcl $expectedFile $administratorsSidText
if (-not $rootExact -or -not $configExact) {{
  throw 'HMSBridge runtime-config ACL did not converge to exact authority'
}}

[pscustomobject]@{{
  ready = $true
  changed = [bool]$changed
  root = [string]$root
  config_path = [string]$configPath
  config_sha256 = [string]$afterSha
  root_owner_sid = [string]$rootAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  config_owner_sid = [string]$configAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  service_sid = [string]$serviceSid
  root_acl_exact = [bool]$rootExact
  config_acl_exact = [bool]$configExact
  root_reparse_point = [bool](($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
  config_reparse_point = [bool](($configItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}}
""".strip()


def _validate_storage_evidence(
    result: dict[str, object],
    path: Path,
) -> dict[str, object]:
    if frozenset(result) != _RESULT_KEYS:
        raise BridgeServiceConfigStorageError(
            "Bridge runtime-config storage evidence schema is invalid"
        )
    if result.get("ready") is not True:
        raise BridgeServiceConfigStorageError(
            "Bridge runtime-config storage is not ready"
        )
    if not isinstance(result.get("changed"), bool):
        raise BridgeServiceConfigStorageError(
            "Bridge runtime-config changed evidence is invalid"
        )
    for key in ("root_acl_exact", "config_acl_exact"):
        if result.get(key) is not True:
            raise BridgeServiceConfigStorageError(
                f"Bridge runtime-config storage evidence is not exact: {key}"
            )
    for key in ("root_reparse_point", "config_reparse_point"):
        if result.get(key) is not False:
            raise BridgeServiceConfigStorageError(
                f"Bridge runtime-config storage contains a reparse point: {key}"
            )
    expected_path = _fixed_config_path(path)
    observed_path = result.get("config_path")
    if (
        not isinstance(observed_path, str)
        or observed_path.casefold() != expected_path.casefold()
    ):
        raise BridgeServiceConfigStorageError(
            "Bridge runtime-config evidence path differs from fixed authority"
        )
    expected_root = str(PureWindowsPath(expected_path).parent)
    observed_root = result.get("root")
    if (
        not isinstance(observed_root, str)
        or observed_root.casefold() != expected_root.casefold()
    ):
        raise BridgeServiceConfigStorageError(
            "Bridge runtime-config root differs from fixed authority"
        )
    for key in ("root_owner_sid", "config_owner_sid"):
        if result.get(key) != _ADMINISTRATORS_SID:
            raise BridgeServiceConfigStorageError(
                f"Bridge runtime-config owner differs from authority: {key}"
            )
    service_sid = result.get("service_sid")
    require_hms_bridge_service_sid(service_sid)
    sha = result.get("config_sha256")
    if (
        not isinstance(sha, str)
        or len(sha) != 64
        or sha != sha.lower()
        or any(char not in "0123456789abcdef" for char in sha)
    ):
        raise BridgeServiceConfigStorageError(
            "Bridge runtime-config SHA-256 evidence is invalid"
        )
    return dict(result)


def provision_bridge_service_runtime_config_storage(
    path: Path = DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
) -> dict[str, object]:
    result = run_powershell_json(
        build_bridge_service_config_storage_script(path, reconcile=True),
        timeout_seconds=60,
    )
    return _validate_storage_evidence(result, path)


def prove_bridge_service_runtime_config_storage(
    path: Path = DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
) -> dict[str, object]:
    result = run_powershell_json(
        build_bridge_service_config_storage_script(path, reconcile=False),
        timeout_seconds=30,
    )
    evidence = _validate_storage_evidence(result, path)
    if evidence.get("changed") is not False:
        raise BridgeServiceConfigStorageError(
            "read-only Bridge runtime-config proof unexpectedly reported mutation"
        )
    return evidence


def load_protected_bridge_service_runtime_config(
    path: Path = DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
):
    """Pin exact ACL and bytes before publishing a parsed production config."""

    before = prove_bridge_service_runtime_config_storage(path)
    from .bridge_service_runtime_config import (
        MAX_BRIDGE_RUNTIME_CONFIG_BYTES,
        parse_bridge_service_runtime_config,
    )

    data = read_file_pinned(
        path,
        max_bytes=MAX_BRIDGE_RUNTIME_CONFIG_BYTES,
        label="Bridge service runtime config",
    )
    if hashlib.sha256(data).hexdigest() != before["config_sha256"]:
        raise BridgeServiceConfigStorageError(
            "Bridge runtime config differs from ACL-pinned pre-read identity"
        )
    config = parse_bridge_service_runtime_config(data)
    after = prove_bridge_service_runtime_config_storage(path)
    if after["config_sha256"] != before["config_sha256"]:
        raise BridgeServiceConfigStorageError(
            "Bridge runtime config changed across protected load boundary"
        )
    return config
