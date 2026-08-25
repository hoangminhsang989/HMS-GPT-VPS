from __future__ import annotations

from pathlib import Path, PureWindowsPath

from .bridge_production_assembly import BridgeRuntimeLayout
from .bridge_service_provisioning_identity import (
    prove_hms_bridge_provisioning_identity,
)
from .bridge_service_runtime_config import BridgeServiceRuntimeConfig
from .powershell import ps_literal, run_powershell_json


DEFAULT_BRIDGE_RUNTIME_ROOT = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime"
)
DEFAULT_BRIDGE_PROVISION_STATE_PATH = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\provision-state.json"
)
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_RESULT_KEYS = frozenset(
    {
        "ready",
        "changed",
        "runtime_root",
        "db_dir",
        "secrets_dir",
        "locks_dir",
        "principal_bindings_dir",
        "service_sid",
        "service_state",
        "service_start_mode",
        "all_acl_exact",
        "reparse_point_found",
    }
)


class BridgeRuntimeLayoutProvisioningError(RuntimeError):
    pass


def _same_windows_path(left: str | Path, right: str | Path) -> bool:
    return str(PureWindowsPath(str(left))).casefold() == str(
        PureWindowsPath(str(right))
    ).casefold()


def validate_bridge_runtime_layout_authority(
    config: BridgeServiceRuntimeConfig,
) -> None:
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise TypeError("config must be a BridgeServiceRuntimeConfig")
    config.validate()
    if not _same_windows_path(config.runtime_root, DEFAULT_BRIDGE_RUNTIME_ROOT):
        raise BridgeRuntimeLayoutProvisioningError(
            "Bridge runtime_root differs from fixed ProgramData authority"
        )
    if not _same_windows_path(
        config.provision_state_path,
        DEFAULT_BRIDGE_PROVISION_STATE_PATH,
    ):
        raise BridgeRuntimeLayoutProvisioningError(
            "Bridge provision_state_path differs from fixed runtime authority"
        )


def build_bridge_runtime_layout_provisioning_script(
    config: BridgeServiceRuntimeConfig,
    *,
    expected_service_sid: str,
    reconcile: bool,
) -> str:
    validate_bridge_runtime_layout_authority(config)
    runtime_root = ps_literal(str(PureWindowsPath(config.runtime_root)))
    expected_sid = ps_literal(expected_service_sid)
    system_sid = ps_literal(_SYSTEM_SID)
    administrators_sid = ps_literal(_ADMINISTRATORS_SID)
    reconcile_literal = "$true" if reconcile else "$false"
    return f"""
$ErrorActionPreference = 'Stop'
$runtimeRoot = [System.IO.Path]::GetFullPath({runtime_root})
$dbDir = [System.IO.Path]::Combine($runtimeRoot, 'db')
$secretsDir = [System.IO.Path]::Combine($runtimeRoot, 'secrets')
$locksDir = [System.IO.Path]::Combine($runtimeRoot, 'locks')
$principalBindingsDir = [System.IO.Path]::Combine($secretsDir, 'principal-bindings')
$expectedServiceSid = {expected_sid}
$systemSidText = {system_sid}
$administratorsSidText = {administrators_sid}
$reconcile = {reconcile_literal}
$serviceAccount = 'NT SERVICE\HMSBridge'
$serviceName = 'HMSBridge'

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
        throw 'HMSBridge runtime layout traverses a reparse point'
      }}
    }}
  }}
}}

function Assert-ServiceAuthority {{
  $rows = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
  if ($rows.Count -ne 1) {{ throw 'Expected exactly one HMSBridge service' }}
  $service = $rows[0]
  if ([string]$service.StartName -ine $serviceAccount) {{
    throw 'HMSBridge runtime layout service account differs'
  }}
  if ([string]$service.StartMode -ne 'Manual') {{
    throw 'HMSBridge must remain Manual during runtime layout provisioning'
  }}
  if ([string]$service.State -ne 'Stopped') {{
    throw 'HMSBridge must remain Stopped during runtime layout provisioning'
  }}
  $resolvedSid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate(
    [System.Security.Principal.SecurityIdentifier]
  ).Value
  if ($resolvedSid -ne $expectedServiceSid) {{
    throw 'HMSBridge service SID differs during runtime layout provisioning'
  }}
  return $service
}}

function New-Sid([string]$text) {{
  return [System.Security.Principal.SecurityIdentifier]::new($text)
}}

function New-InheritableRule(
  [System.Security.Principal.SecurityIdentifier]$sid,
  [System.Security.AccessControl.FileSystemRights]$rights
) {{
  return [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    $rights,
    (
      [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    ),
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}}

function New-LayoutAcl {{
  $acl = [System.Security.AccessControl.DirectorySecurity]::new()
  $admins = New-Sid $administratorsSidText
  $system = New-Sid $systemSidText
  $service = New-Sid $expectedServiceSid
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($admins)
  $acl.AddAccessRule((New-InheritableRule $system ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-InheritableRule $admins ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-InheritableRule $service (
    [System.Security.AccessControl.FileSystemRights]::Modify -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize
  )))
  return $acl
}}

function Test-LayoutAcl($acl) {{
  if (
    $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $administratorsSidText -or
    -not $acl.AreAccessRulesProtected
  ) {{ return $false }}
  $expected = @{{}}
  $expected[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
  $expected[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
  $expected[$expectedServiceSid] = (
    [System.Security.AccessControl.FileSystemRights]::Modify -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize
  )
  $wantedInheritance = (
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  )
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne $expected.Count) {{ return $false }}
  foreach ($rule in $rules) {{
    if (
      $rule.IsInherited -or
      $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
      $rule.InheritanceFlags -ne $wantedInheritance -or
      $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
    ) {{ return $false }}
    $sid = $rule.IdentityReference.Value
    if (-not $expected.ContainsKey($sid)) {{ return $false }}
    if ([int64]$rule.FileSystemRights -ne [int64]$expected[$sid]) {{ return $false }}
  }}
  return $true
}}

Assert-ServiceAuthority | Out-Null
$paths = @($runtimeRoot, $dbDir, $secretsDir, $locksDir, $principalBindingsDir)
foreach ($path in $paths) {{
  Assert-NoReparseChain $path
  if (-not (Test-Path -LiteralPath $path -PathType Container)) {{
    if (-not $reconcile) {{
      throw 'HMSBridge runtime layout directory is missing'
    }}
    New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
  }}
  Assert-NoReparseChain $path
}}

$changed = $false
foreach ($path in $paths) {{
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
  if (-not (Test-LayoutAcl $acl)) {{
    if (-not $reconcile) {{
      throw 'HMSBridge runtime layout ACL differs from exact authority'
    }}
    Set-Acl -LiteralPath $path -AclObject (New-LayoutAcl) -ErrorAction Stop
    $changed = $true
  }}
}}

$allExact = $true
$reparseFound = $false
foreach ($path in $paths) {{
  Assert-NoReparseChain $path
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    $reparseFound = $true
  }}
  if (-not (Test-LayoutAcl (Get-Acl -LiteralPath $path -ErrorAction Stop))) {{
    $allExact = $false
  }}
}}
$descendants = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -Force -ErrorAction Stop)
foreach ($item in $descendants) {{
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    $reparseFound = $true
  }}
}}
if ($reparseFound -or -not $allExact) {{
  throw 'HMSBridge runtime layout final proof failed'
}}
$service = Assert-ServiceAuthority
[pscustomobject]@{{
  ready = $true
  changed = [bool]$changed
  runtime_root = [string]$runtimeRoot
  db_dir = [string]$dbDir
  secrets_dir = [string]$secretsDir
  locks_dir = [string]$locksDir
  principal_bindings_dir = [string]$principalBindingsDir
  service_sid = [string]$expectedServiceSid
  service_state = [string]$service.State
  service_start_mode = [string]$service.StartMode
  all_acl_exact = [bool]$allExact
  reparse_point_found = [bool]$reparseFound
}}
""".strip()


def _validate_layout_evidence(
    result: dict[str, object],
    config: BridgeServiceRuntimeConfig,
    *,
    expected_service_sid: str,
    require_unchanged: bool,
) -> dict[str, object]:
    if frozenset(result) != _RESULT_KEYS:
        raise BridgeRuntimeLayoutProvisioningError(
            "Bridge runtime layout evidence schema is invalid"
        )
    expected = {
        "ready": True,
        "service_sid": expected_service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "all_acl_exact": True,
        "reparse_point_found": False,
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise BridgeRuntimeLayoutProvisioningError(
                f"Bridge runtime layout evidence differs: {key}"
            )
    if not isinstance(result.get("changed"), bool):
        raise BridgeRuntimeLayoutProvisioningError(
            "Bridge runtime layout changed evidence is invalid"
        )
    if require_unchanged and result.get("changed") is not False:
        raise BridgeRuntimeLayoutProvisioningError(
            "observer-only Bridge runtime layout proof reported mutation"
        )
    expected_paths = {
        "runtime_root": PureWindowsPath(config.runtime_root),
        "db_dir": PureWindowsPath(config.runtime_root) / "db",
        "secrets_dir": PureWindowsPath(config.runtime_root) / "secrets",
        "locks_dir": PureWindowsPath(config.runtime_root) / "locks",
        "principal_bindings_dir": (
            PureWindowsPath(config.runtime_root) / "secrets" / "principal-bindings"
        ),
    }
    for key, wanted in expected_paths.items():
        observed = result.get(key)
        if (
            not isinstance(observed, str)
            or str(PureWindowsPath(observed)).casefold()
            != str(wanted).casefold()
        ):
            raise BridgeRuntimeLayoutProvisioningError(
                f"Bridge runtime layout path evidence differs: {key}"
            )
    return dict(result)


def _run_layout(
    config: BridgeServiceRuntimeConfig,
    *,
    expected_service_sid: str,
    reconcile: bool,
) -> dict[str, object]:
    return _validate_layout_evidence(
        run_powershell_json(
            build_bridge_runtime_layout_provisioning_script(
                config,
                expected_service_sid=expected_service_sid,
                reconcile=reconcile,
            ),
            timeout_seconds=120,
        ),
        config,
        expected_service_sid=expected_service_sid,
        require_unchanged=not reconcile,
    )


def provision_bridge_runtime_layout(
    config: BridgeServiceRuntimeConfig,
) -> dict[str, object]:
    """Provision and prove the writable Bridge runtime directories before service start."""

    validate_bridge_runtime_layout_authority(config)
    pre = prove_hms_bridge_provisioning_identity()
    service_sid = pre.get("service_sid")
    if not isinstance(service_sid, str):
        raise BridgeRuntimeLayoutProvisioningError(
            "HMSBridge service SID proof is invalid"
        )

    changed = _run_layout(
        config,
        expected_service_sid=service_sid,
        reconcile=True,
    )["changed"]
    proof = _run_layout(
        config,
        expected_service_sid=service_sid,
        reconcile=False,
    )
    layout = BridgeRuntimeLayout.prepare(Path(config.runtime_root))
    if (
        not _same_windows_path(layout.root, config.runtime_root)
        or layout.db_dir.name != "db"
        or layout.secrets_dir.name != "secrets"
        or layout.locks_dir.name != "locks"
        or layout.principal_bindings_dir.name != "principal-bindings"
    ):
        raise BridgeRuntimeLayoutProvisioningError(
            "BridgeRuntimeLayout code-level preparation differs from provisioned authority"
        )
    post = prove_hms_bridge_provisioning_identity()
    if post.get("service_sid") != service_sid:
        raise BridgeRuntimeLayoutProvisioningError(
            "HMSBridge service SID changed across runtime layout provisioning"
        )
    return {
        **proof,
        "changed": changed,
        "code_layout_prepared": True,
        "post_identity_proven": True,
    }
