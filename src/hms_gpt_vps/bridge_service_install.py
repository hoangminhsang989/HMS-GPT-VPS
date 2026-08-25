from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath

from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    HMS_BRIDGE_SERVICE_NAME,
    require_hms_bridge_service_sid,
)
from .powershell import ps_literal, run_powershell_json


_RESULT_KEYS = frozenset(
    {
        "ready",
        "created",
        "service_name",
        "display_name",
        "service_account",
        "service_sid",
        "service_sid_type",
        "start_mode",
        "state",
        "binary_path",
        "binary_sha256",
        "service_started",
        "administrators_assignment_performed",
        "hyperv_admin_assignment_performed",
    }
)


class HmsBridgeServiceInstallError(RuntimeError):
    pass


def _require_sha256(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise HmsBridgeServiceInstallError(
            "binary_sha256 must be canonical lowercase SHA-256 hex"
        )
    return value


@dataclass(frozen=True)
class HmsBridgeServiceInstallConfig:
    binary_path: str
    binary_sha256: str
    expected_service_sid: str
    service_name: str = HMS_BRIDGE_SERVICE_NAME
    display_name: str = "HMS GPT VPS Bridge"

    def validate(self) -> None:
        if self.service_name != HMS_BRIDGE_SERVICE_NAME:
            raise HmsBridgeServiceInstallError(
                "production Bridge service name is fixed to HMSBridge"
            )
        if self.display_name != "HMS GPT VPS Bridge":
            raise HmsBridgeServiceInstallError(
                "production Bridge display name differs from authority"
            )
        if not isinstance(self.binary_path, str) or not self.binary_path.strip():
            raise HmsBridgeServiceInstallError("binary_path is required")
        if self.binary_path != self.binary_path.strip():
            raise HmsBridgeServiceInstallError("binary_path must be canonical text")
        path = PureWindowsPath(self.binary_path)
        if not path.is_absolute():
            raise HmsBridgeServiceInstallError(
                "binary_path must be an absolute Windows path"
            )
        if (
            len(path.drive) != 2
            or path.drive[1] != ":"
            or path.root != "\\"
            or any(part in {".", ".."} for part in path.parts)
        ):
            raise HmsBridgeServiceInstallError(
                "binary_path must be a canonical local-drive Windows path"
            )
        canonical = str(path)
        if self.binary_path != canonical:
            raise HmsBridgeServiceInstallError(
                "binary_path must use canonical Windows path text"
            )
        if (
            any(char in self.binary_path for char in '"<>|*?')
            or any(ord(char) < 32 for char in self.binary_path)
        ):
            raise HmsBridgeServiceInstallError(
                "binary_path contains unsupported Windows path characters"
            )
        if path.name.casefold() != "hms-bridge.exe":
            raise HmsBridgeServiceInstallError(
                "production Bridge executable must be hms-bridge.exe"
            )
        _require_sha256(self.binary_sha256)
        require_hms_bridge_service_sid(self.expected_service_sid)


def build_hms_bridge_service_install_script(
    config: HmsBridgeServiceInstallConfig,
) -> str:
    config.validate()
    service_name = ps_literal(config.service_name)
    display_name = ps_literal(config.display_name)
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    binary_path = ps_literal(str(PureWindowsPath(config.binary_path)))
    binary_sha256 = ps_literal(config.binary_sha256)
    expected_service_sid = ps_literal(config.expected_service_sid)

    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$displayName = {display_name}
$serviceAccount = {service_account}
$binaryPath = [System.IO.Path]::GetFullPath({binary_path})
$expectedBinarySha256 = {binary_sha256}
$expectedServiceSid = {expected_service_sid}
$expectedCommand = '"' + $binaryPath + '" service'
$created = $false

function Assert-NoReparseChain([string]$path) {{
  $full = [System.IO.Path]::GetFullPath($path)
  $root = [System.IO.Path]::GetPathRoot($full)
  $relative = $full.Substring($root.Length)
  $current = $root
  foreach ($segment in @($relative.Split([System.IO.Path]::DirectorySeparatorChar, [System.StringSplitOptions]::RemoveEmptyEntries))) {{
    $current = [System.IO.Path]::Combine($current, $segment)
    if (Test-Path -LiteralPath $current) {{
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
        throw 'HMSBridge executable authority traverses a reparse point'
      }}
    }}
  }}
}}

function Get-HmsBridgeServiceObservation {{
  $rows = @(Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
  if ($rows.Count -eq 0) {{ return $null }}
  if ($rows.Count -ne 1) {{ throw 'Expected exactly one HMSBridge SCM service' }}
  return $rows[0]
}}

Assert-NoReparseChain $binaryPath
if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {{
  throw 'Pinned HMSBridge executable is missing'
}}
$beforeHash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($beforeHash -ne $expectedBinarySha256) {{
  throw 'HMSBridge executable SHA-256 differs from deployment authority'
}}

$existing = Get-HmsBridgeServiceObservation
if ($null -ne $existing) {{
  if ([string]$existing.State -ne 'Stopped') {{
    throw 'Existing HMSBridge service must be stopped during staging reconciliation'
  }}
  if ([string]$existing.PathName -ne $expectedCommand) {{
    throw 'Existing HMSBridge executable command conflicts with deployment authority'
  }}
  if ([string]$existing.StartName -ine $serviceAccount) {{
    throw 'Existing HMSBridge service account conflicts with virtual-account authority'
  }}
  if ([string]$existing.StartMode -ne 'Manual') {{
    throw 'Existing HMSBridge service must remain Manual until runtime qualification'
  }}
}} else {{
  & sc.exe create $serviceName `
    'type=' 'own' `
    'binPath=' $expectedCommand `
    'start=' 'demand' `
    'error=' 'normal' `
    'obj=' $serviceAccount `
    'DisplayName=' $displayName | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'sc.exe create HMSBridge failed' }}
  $created = $true
}}

& sc.exe sidtype $serviceName unrestricted | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to configure HMSBridge service SID type' }}
& sc.exe description $serviceName 'HMS low-privilege private Agent Bridge' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to configure HMSBridge description' }}
& sc.exe failure $serviceName 'reset=' '86400' 'actions=' 'restart/5000/restart/15000/restart/60000' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to configure HMSBridge failure policy' }}
& sc.exe failureflag $serviceName '1' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to configure HMSBridge failure flag' }}

$sidInfo = (& sc.exe qsidtype $serviceName 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $sidInfo -notmatch 'UNRESTRICTED') {{
  throw 'HMSBridge service SID type is not UNRESTRICTED'
}}
$account = [System.Security.Principal.NTAccount]::new($serviceAccount)
$serviceSid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
if ($serviceSid -ne $expectedServiceSid -or -not $serviceSid.StartsWith('S-1-5-80-')) {{
  throw 'Resolved HMSBridge virtual-account SID differs from deployment authority'
}}

$observed = Get-HmsBridgeServiceObservation
if ($null -eq $observed) {{ throw 'HMSBridge service disappeared after staging' }}
if ([string]$observed.State -ne 'Stopped') {{ throw 'HMSBridge service started during staging' }}
if ([string]$observed.StartMode -ne 'Manual') {{ throw 'HMSBridge start mode changed during staging' }}
if ([string]$observed.StartName -ine $serviceAccount) {{ throw 'HMSBridge service account changed during staging' }}
if ([string]$observed.PathName -ne $expectedCommand) {{ throw 'HMSBridge command changed during staging' }}
if ([string]$observed.DisplayName -ne $displayName) {{ throw 'HMSBridge display name differs from authority' }}
Assert-NoReparseChain $binaryPath
$afterHash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($afterHash -ne $expectedBinarySha256 -or $afterHash -ne $beforeHash) {{
  throw 'HMSBridge executable changed during SCM staging'
}}

[pscustomobject]@{{
  ready = $true
  created = [bool]$created
  service_name = [string]$serviceName
  display_name = [string]$displayName
  service_account = [string]$serviceAccount
  service_sid = [string]$serviceSid
  service_sid_type = 'UNRESTRICTED'
  start_mode = 'Manual'
  state = 'Stopped'
  binary_path = [string]$binaryPath
  binary_sha256 = [string]$afterHash
  service_started = $false
  administrators_assignment_performed = $false
  hyperv_admin_assignment_performed = $false
}}
""".strip()


def install_hms_bridge_service_authority(
    config: HmsBridgeServiceInstallConfig,
) -> dict[str, object]:
    if not isinstance(config, HmsBridgeServiceInstallConfig):
        raise TypeError("config must be an HmsBridgeServiceInstallConfig")
    config.validate()
    result = run_powershell_json(
        build_hms_bridge_service_install_script(config),
        timeout_seconds=90,
    )
    if frozenset(result) != _RESULT_KEYS:
        raise HmsBridgeServiceInstallError("HMSBridge SCM evidence schema is invalid")
    expected = {
        "ready": True,
        "service_name": HMS_BRIDGE_SERVICE_NAME,
        "display_name": config.display_name,
        "service_account": HMS_BRIDGE_SERVICE_ACCOUNT,
        "service_sid": config.expected_service_sid,
        "service_sid_type": "UNRESTRICTED",
        "start_mode": "Manual",
        "state": "Stopped",
        "binary_path": str(PureWindowsPath(config.binary_path)),
        "binary_sha256": config.binary_sha256,
        "service_started": False,
        "administrators_assignment_performed": False,
        "hyperv_admin_assignment_performed": False,
    }
    for key, wanted in expected.items():
        observed = result.get(key)
        if isinstance(wanted, str):
            if not isinstance(observed, str) or observed.casefold() != wanted.casefold():
                raise HmsBridgeServiceInstallError(
                    f"HMSBridge SCM evidence differs from authority: {key}"
                )
        elif observed is not wanted:
            raise HmsBridgeServiceInstallError(
                f"HMSBridge SCM evidence differs from authority: {key}"
            )
    if not isinstance(result.get("created"), bool):
        raise HmsBridgeServiceInstallError("HMSBridge created evidence is invalid")
    return dict(result)
