from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath

from .bridge_service_config_storage import (
    load_protected_bridge_service_runtime_config,
    prove_bridge_service_runtime_config_storage,
)
from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    HMS_BRIDGE_SERVICE_NAME,
    require_hms_bridge_service_sid,
)
from .bridge_service_provisioning_identity import (
    prove_hms_bridge_provisioning_identity,
)
from .bridge_service_runtime_config import (
    DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
    BridgeServiceRuntimeConfig,
)
from .powershell import ps_literal, run_powershell_json


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_RESULT_KEYS = frozenset(
    {
        "ready",
        "created",
        "config_path",
        "config_sha256",
        "service_sid",
        "service_state",
        "service_start_mode",
        "root_acl_exact",
        "config_acl_exact",
        "config_reparse_point",
    }
)


class BridgeServiceRuntimeConfigPublicationError(RuntimeError):
    pass


def canonical_bridge_service_runtime_config_bytes(
    config: BridgeServiceRuntimeConfig,
) -> bytes:
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise TypeError("config must be a BridgeServiceRuntimeConfig")
    config.validate()
    return json.dumps(
        config.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def bridge_service_runtime_config_sha256(
    config: BridgeServiceRuntimeConfig,
) -> str:
    return hashlib.sha256(
        canonical_bridge_service_runtime_config_bytes(config)
    ).hexdigest()


def _fixed_config_path(path: Path) -> str:
    if not isinstance(path, Path):
        raise TypeError("path must be pathlib.Path")
    observed = str(PureWindowsPath(str(path)))
    expected = str(PureWindowsPath(str(DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH)))
    if observed.casefold() != expected.casefold():
        raise BridgeServiceRuntimeConfigPublicationError(
            "Bridge runtime config publication path differs from fixed authority"
        )
    return expected


def build_bridge_service_runtime_config_publication_script(
    config: BridgeServiceRuntimeConfig,
    *,
    expected_service_sid: str,
    path: Path = DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
) -> str:
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise TypeError("config must be a BridgeServiceRuntimeConfig")
    config.validate()
    service_sid = require_hms_bridge_service_sid(expected_service_sid)
    config_path = ps_literal(_fixed_config_path(path))
    service_name = ps_literal(HMS_BRIDGE_SERVICE_NAME)
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    expected_sid = ps_literal(service_sid)
    expected_sha = ps_literal(bridge_service_runtime_config_sha256(config))
    payload = ps_literal(
        base64.b64encode(
            canonical_bridge_service_runtime_config_bytes(config)
        ).decode("ascii")
    )
    system_sid = ps_literal(_SYSTEM_SID)
    administrators_sid = ps_literal(_ADMINISTRATORS_SID)
    return f"""
$ErrorActionPreference = 'Stop'
$configPath = [System.IO.Path]::GetFullPath({config_path})
$root = [System.IO.Path]::GetDirectoryName($configPath)
$serviceName = {service_name}
$serviceAccount = {service_account}
$expectedServiceSid = {expected_sid}
$expectedSha256 = {expected_sha}
$payloadB64 = {payload}
$systemSidText = {system_sid}
$administratorsSidText = {administrators_sid}
$tempPath = $null
$published = $false

function Assert-NoReparseExistingChain([string]$path) {{
  $full = [System.IO.Path]::GetFullPath($path)
  $driveRoot = [System.IO.Path]::GetPathRoot($full)
  $relative = $full.Substring($driveRoot.Length)
  $current = $driveRoot
  foreach ($segment in @($relative.Split([System.IO.Path]::DirectorySeparatorChar, [System.StringSplitOptions]::RemoveEmptyEntries))) {{
    $current = [System.IO.Path]::Combine($current, $segment)
    if (Test-Path -LiteralPath $current) {{
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
        throw 'Bridge runtime config publication traverses a reparse point'
      }}
    }}
  }}
}}

function Get-ExactService {{
  $rows = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
  if ($rows.Count -ne 1) {{
    throw 'Expected exactly one HMSBridge SCM service during config publication'
  }}
  return $rows[0]
}}

function Assert-ProvisioningAuthority {{
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  if ($null -eq $identity.User) {{
    throw 'Bridge runtime config publication process token has no user SID'
  }}
  $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    throw 'Bridge runtime config publication requires an elevated Administrator token'
  }}
  $service = Get-ExactService
  if ([string]$service.StartName -ine $serviceAccount) {{
    throw 'HMSBridge service account drifted during config publication'
  }}
  if ([string]$service.StartMode -ne 'Manual') {{
    throw 'HMSBridge must remain Manual during config publication'
  }}
  if ([string]$service.State -ne 'Stopped') {{
    throw 'HMSBridge must remain Stopped during config publication'
  }}
  $resolvedSid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate(
    [System.Security.Principal.SecurityIdentifier]
  ).Value
  if ($resolvedSid -ne $expectedServiceSid) {{
    throw 'HMSBridge service SID drifted during config publication'
  }}
  return $service
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
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}}

function Test-ExactAcl(
  [System.Security.AccessControl.FileSystemSecurity]$acl,
  [hashtable]$expected,
  [string]$ownerSidText
) {{
  if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $ownerSidText) {{
    return $false
  }}
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
    if ([int64]$rule.FileSystemRights -ne [int64]$expected[$sid]) {{
      return $false
    }}
  }}
  return $true
}}

function Get-BytesSha256([byte[]]$bytes) {{
  $algorithm = [System.Security.Cryptography.SHA256]::Create()
  try {{
    $hash = $algorithm.ComputeHash($bytes)
  }} finally {{
    $algorithm.Dispose()
  }}
  return (($hash | ForEach-Object {{ $_.ToString('x2') }}) -join '')
}}

try {{
  Assert-ProvisioningAuthority | Out-Null
  Assert-NoReparseExistingChain $root
  Assert-NoReparseExistingChain $configPath
  if (Test-Path -LiteralPath $configPath) {{
    throw 'Bridge runtime config already exists; publication is create-only'
  }}

  if (-not (Test-Path -LiteralPath $root -PathType Container)) {{
    New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null
  }}
  Assert-NoReparseExistingChain $root
  if (-not (Test-Path -LiteralPath $root -PathType Container)) {{
    throw 'Bridge runtime config root creation failed'
  }}

  $systemSid = New-Sid $systemSidText
  $administratorsSid = New-Sid $administratorsSidText
  $serviceSid = New-Sid $expectedServiceSid

  $rootAcl = [System.Security.AccessControl.DirectorySecurity]::new()
  $rootAcl.SetAccessRuleProtection($true, $false)
  $rootAcl.SetOwner($administratorsSid)
  $rootAcl.AddAccessRule((New-Rule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $rootAcl.AddAccessRule((New-Rule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $rootAcl.AddAccessRule((New-Rule $serviceSid (
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize
  )))
  Set-Acl -LiteralPath $root -AclObject $rootAcl -ErrorAction Stop

  $bytes = [Convert]::FromBase64String($payloadB64)
  if ((Get-BytesSha256 $bytes) -ne $expectedSha256) {{
    throw 'Bridge runtime config payload SHA-256 differs before publication'
  }}

  $tempPath = $configPath + '.hms-' + [guid]::NewGuid().ToString('N') + '.tmp'
  $stream = [System.IO.FileStream]::new(
    $tempPath,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None
  )
  try {{
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
  }} finally {{
    $stream.Dispose()
  }}
  if ((Get-FileHash -LiteralPath $tempPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -ne $expectedSha256) {{
    throw 'Bridge runtime config temp SHA-256 differs from canonical payload'
  }}

  $fileAcl = [System.Security.AccessControl.FileSecurity]::new()
  $fileAcl.SetAccessRuleProtection($true, $false)
  $fileAcl.SetOwner($administratorsSid)
  $fileAcl.AddAccessRule((New-Rule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $fileAcl.AddAccessRule((New-Rule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $fileAcl.AddAccessRule((New-Rule $serviceSid (
    [System.Security.AccessControl.FileSystemRights]::Read -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize
  )))
  Set-Acl -LiteralPath $tempPath -AclObject $fileAcl -ErrorAction Stop

  Assert-ProvisioningAuthority | Out-Null
  if (Test-Path -LiteralPath $configPath) {{
    throw 'Bridge runtime config appeared during create-only publication'
  }}
  [System.IO.File]::Move($tempPath, $configPath)
  $tempPath = $null
  $published = $true

  Assert-NoReparseExistingChain $configPath
  $configItem = Get-Item -LiteralPath $configPath -Force -ErrorAction Stop
  if (($configItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    throw 'Published Bridge runtime config is a reparse point'
  }}
  $actualSha = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($actualSha -ne $expectedSha256) {{
    throw 'Published Bridge runtime config SHA-256 differs from authority'
  }}

  $expectedRoot = @{{}}
  $expectedRoot[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
  $expectedRoot[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
  $expectedRoot[$expectedServiceSid] = (
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize
  )
  $expectedFile = @{{}}
  $expectedFile[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
  $expectedFile[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
  $expectedFile[$expectedServiceSid] = (
    [System.Security.AccessControl.FileSystemRights]::Read -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize
  )
  $observedRootAcl = Get-Acl -LiteralPath $root -ErrorAction Stop
  $observedFileAcl = Get-Acl -LiteralPath $configPath -ErrorAction Stop
  $rootExact = Test-ExactAcl $observedRootAcl $expectedRoot $administratorsSidText
  $fileExact = Test-ExactAcl $observedFileAcl $expectedFile $administratorsSidText
  if (-not $rootExact -or -not $fileExact) {{
    throw 'Bridge runtime config publication ACL differs from exact authority'
  }}

  $service = Assert-ProvisioningAuthority
  [pscustomobject]@{{
    ready = $true
    created = $true
    config_path = [string]$configPath
    config_sha256 = [string]$actualSha
    service_sid = [string]$expectedServiceSid
    service_state = [string]$service.State
    service_start_mode = [string]$service.StartMode
    root_acl_exact = [bool]$rootExact
    config_acl_exact = [bool]$fileExact
    config_reparse_point = $false
  }}
}} catch {{
  if ($null -ne $tempPath -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {{
    try {{ Remove-Item -LiteralPath $tempPath -Force -ErrorAction Stop }} catch {{ }}
  }}
  if ($published -and (Test-Path -LiteralPath $configPath -PathType Leaf)) {{
    try {{
      Assert-NoReparseExistingChain $configPath
      $service = Get-ExactService
      $sha = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
      if (
        [string]$service.State -eq 'Stopped' -and
        [string]$service.StartMode -eq 'Manual' -and
        $sha -eq $expectedSha256
      ) {{
        Remove-Item -LiteralPath $configPath -Force -ErrorAction Stop
      }}
    }} catch {{ }}
  }}
  throw
}}
""".strip()


def _validate_publication_evidence(
    result: dict[str, object],
    *,
    expected_service_sid: str,
    expected_sha256: str,
    path: Path,
) -> dict[str, object]:
    if frozenset(result) != _RESULT_KEYS:
        raise BridgeServiceRuntimeConfigPublicationError(
            "Bridge runtime config publication evidence schema is invalid"
        )
    expected = {
        "ready": True,
        "created": True,
        "config_sha256": expected_sha256,
        "service_sid": expected_service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "root_acl_exact": True,
        "config_acl_exact": True,
        "config_reparse_point": False,
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise BridgeServiceRuntimeConfigPublicationError(
                f"Bridge runtime config publication evidence differs: {key}"
            )
    observed_path = result.get("config_path")
    expected_path = _fixed_config_path(path)
    if (
        not isinstance(observed_path, str)
        or observed_path.casefold() != expected_path.casefold()
    ):
        raise BridgeServiceRuntimeConfigPublicationError(
            "Bridge runtime config publication path evidence differs"
        )
    return dict(result)


def publish_bridge_service_runtime_config_create_only(
    config: BridgeServiceRuntimeConfig,
    *,
    path: Path = DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
) -> dict[str, object]:
    """Create the fixed production runtime config exactly once under a stopped HMSBridge."""

    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise TypeError("config must be a BridgeServiceRuntimeConfig")
    config.validate()
    expected_sha = bridge_service_runtime_config_sha256(config)

    pre = prove_hms_bridge_provisioning_identity()
    service_sid = require_hms_bridge_service_sid(pre.get("service_sid"))

    result = run_powershell_json(
        build_bridge_service_runtime_config_publication_script(
            config,
            expected_service_sid=service_sid,
            path=path,
        ),
        timeout_seconds=90,
    )
    evidence = _validate_publication_evidence(
        result,
        expected_service_sid=service_sid,
        expected_sha256=expected_sha,
        path=path,
    )

    storage = prove_bridge_service_runtime_config_storage(path)
    if storage.get("changed") is not False:
        raise BridgeServiceRuntimeConfigPublicationError(
            "read-only runtime-config storage proof reported mutation"
        )
    if storage.get("config_sha256") != expected_sha:
        raise BridgeServiceRuntimeConfigPublicationError(
            "runtime-config storage SHA-256 differs after publication"
        )

    loaded = load_protected_bridge_service_runtime_config(path)
    if (
        canonical_bridge_service_runtime_config_bytes(loaded)
        != canonical_bridge_service_runtime_config_bytes(config)
    ):
        raise BridgeServiceRuntimeConfigPublicationError(
            "protected runtime-config load differs from published authority"
        )

    post = prove_hms_bridge_provisioning_identity()
    if post.get("service_sid") != service_sid:
        raise BridgeServiceRuntimeConfigPublicationError(
            "HMSBridge service SID changed across runtime-config publication"
        )
    return {
        **evidence,
        "protected_load_proven": True,
        "post_identity_proven": True,
    }
