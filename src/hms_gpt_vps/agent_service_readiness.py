from __future__ import annotations

from pathlib import PureWindowsPath

from .agent_package import AgentPackageManifest
from .agent_package_powershell import (
    POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION,
    package_manifest_ps_literal,
)
from .agent_service_install import AgentServiceConfig
from .agent_service_runtime_config import AgentServiceRuntimeConfig
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


def _same_windows_path(left: str, right: str) -> bool:
    return str(PureWindowsPath(left)).casefold() == str(PureWindowsPath(right)).casefold()


def _validate_runtime_alignment(
    service: AgentServiceConfig,
    runtime: AgentServiceRuntimeConfig,
) -> None:
    runtime.validate()
    if not _same_windows_path(runtime.workspace_root, service.workspace_path):
        raise ValueError("runtime config workspace_root conflicts with service ACL target")
    if not _same_windows_path(runtime.state_root, service.state_path):
        raise ValueError("runtime config state_root conflicts with service ACL target")


def build_agent_service_readiness_script(
    config: AgentServiceConfig,
    *,
    package_manifest: AgentPackageManifest,
    runtime_config: AgentServiceRuntimeConfig,
) -> str:
    """Build a read-only guest probe for the Windows service bootstrap boundary.

    The probe re-verifies the entire immutable onedir package tree, SCM
    configuration, exact runtime config, per-service SID and filesystem ACLs.
    Application protocol health remains a separate `/healthz` gate.
    """
    config.validate()
    package_manifest.validate()
    _validate_runtime_alignment(config, runtime_config)

    service_name = ps_literal(config.service_name)
    agent_root = ps_literal(config.agent_root_path)
    package_root = ps_literal(config.package_path)
    binary_path = ps_literal(config.binary_path)
    runtime_config_path = ps_literal(config.runtime_config_path)
    workspace = ps_literal(config.workspace_path)
    state_path = ps_literal(config.state_path)
    expected_hash = ps_literal(package_manifest.sha256.lower())
    expected_runtime_config_hash = ps_literal(runtime_config.sha256())
    package_manifest_payload = package_manifest_ps_literal(package_manifest)

    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$agentRoot = {agent_root}
$packageRoot = {package_root}
$binaryPath = {binary_path}
$runtimeConfigPath = {runtime_config_path}
$workspace = {workspace}
$statePath = {state_path}
$expectedHash = {expected_hash}
$expectedRuntimeConfigHash = {expected_runtime_config_hash}
$packageManifestPayload = {package_manifest_payload}
$servicePrincipal = "NT SERVICE\\$serviceName"
$expectedQuotedCommand = '"' + $binaryPath + '" service'
$expectedUnquotedCommand = $binaryPath + ' service'

{POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$serviceExists = $null -ne $service
$serviceRunning = $serviceExists -and $service.Status -eq 'Running'

$startNameOk = $false
$commandOk = $false
if ($serviceExists) {{
  $cim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
  $startNameOk = $cim.StartName -eq 'NT AUTHORITY\\LocalService'
  $commandOk = [bool](
    $cim.PathName -eq $expectedQuotedCommand -or
    (($binaryPath -notmatch '\\s') -and $cim.PathName -eq $expectedUnquotedCommand)
  )
}}

$agentRootLayoutOk = (
  (Split-Path -Parent $packageRoot) -eq $agentRoot -and
  (Split-Path -Parent $binaryPath) -eq $packageRoot -and
  (Split-Path -Parent $runtimeConfigPath) -eq $agentRoot
)

$packageTreeOk = $false
$binaryHashOk = $false
$actualHash = $null
$packageFileCount = 0
$packageTotalSize = 0
if ($agentRootLayoutOk -and (Test-Path -LiteralPath $packageRoot -PathType Container)) {{
  $packageProof = Test-HmsAgentPackageTree $packageRoot $packageManifestPayload
  $actualHash = [string]$packageProof.entrypoint_sha256
  $binaryHashOk = $actualHash -eq $expectedHash
  $packageFileCount = [int]$packageProof.file_count
  $packageTotalSize = [int64]$packageProof.total_size
  $packageTreeOk = [bool](
    $binaryHashOk -and
    $packageFileCount -eq {package_manifest.file_count} -and
    $packageTotalSize -eq {package_manifest.total_size}
  )
}}

$runtimeConfigExists = Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf
$runtimeConfigHashOk = $false
$actualRuntimeConfigHash = $null
if ($runtimeConfigExists) {{
  $actualRuntimeConfigHash = Get-HmsSha256 $runtimeConfigPath
  $runtimeConfigHashOk = $actualRuntimeConfigHash -eq $expectedRuntimeConfigHash
}}

$sidTypeOk = $false
$serviceSid = $null
if ($serviceExists) {{
  $sidInfo = (& sc.exe qsidtype $serviceName 2>&1 | Out-String)
  $sidTypeOk = $LASTEXITCODE -eq 0 -and $sidInfo -match 'UNRESTRICTED'
  if ($sidTypeOk) {{
    $serviceSid = ([System.Security.Principal.NTAccount]::new($servicePrincipal)).Translate(
      [System.Security.Principal.SecurityIdentifier]
    )
  }}
}}

function Test-HmsAclRight([string]$Path, [string[]]$AcceptedRights) {{
  if ($null -eq $serviceSid) {{ return $false }}
  if (-not ([System.IO.Directory]::Exists($Path) -or [System.IO.File]::Exists($Path))) {{
    return $false
  }}

  $aclOutput = (& icacls.exe $Path 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0) {{
    throw "icacls.exe failed while reading HMS ACL: $Path"
  }}

  $identities = @(
    $servicePrincipal,
    [string]$serviceSid.Value,
    ('*' + [string]$serviceSid.Value)
  )
  foreach ($line in ($aclOutput -split "`r?`n")) {{
    $identityMatched = $false
    foreach ($identity in $identities) {{
      if ($line.IndexOf($identity, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {{
        $identityMatched = $true
        break
      }}
    }}
    if (-not $identityMatched) {{ continue }}
    if ($line.IndexOf('(DENY)', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {{
      return $false
    }}
    foreach ($right in $AcceptedRights) {{
      $token = '(' + $right + ')'
      if ($line.IndexOf($token, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {{
        return $true
      }}
    }}
  }}
  return $false
}}

$agentRootReadExecute = Test-HmsAclRight $agentRoot @('RX', 'M', 'F')
$runtimeConfigRead = Test-HmsAclRight $runtimeConfigPath @('R', 'RX', 'M', 'F')
$workspaceModify = Test-HmsAclRight $workspace @('M', 'F')
$stateModify = Test-HmsAclRight $statePath @('M', 'F')

$serviceReady = [bool](
  $serviceExists -and
  $serviceRunning -and
  $startNameOk -and
  $commandOk -and
  $agentRootLayoutOk -and
  $packageTreeOk -and
  $binaryHashOk -and
  $runtimeConfigExists -and
  $runtimeConfigHashOk -and
  $sidTypeOk -and
  $agentRootReadExecute -and
  $runtimeConfigRead -and
  $workspaceModify -and
  $stateModify
)

[pscustomobject]@{{
  service_ready = $serviceReady
  application_health = 'NOT_IMPLEMENTED'
  service_exists = [bool]$serviceExists
  service_running = [bool]$serviceRunning
  local_service_account = [bool]$startNameOk
  binary_command_ok = [bool]$commandOk
  agent_root_layout_ok = [bool]$agentRootLayoutOk
  package_tree_ok = [bool]$packageTreeOk
  package_file_count = [int]$packageFileCount
  package_total_size = [int64]$packageTotalSize
  binary_sha256_ok = [bool]$binaryHashOk
  binary_sha256 = $actualHash
  runtime_config_exists = [bool]$runtimeConfigExists
  runtime_config_sha256_ok = [bool]$runtimeConfigHashOk
  runtime_config_sha256 = $actualRuntimeConfigHash
  runtime_config_read = [bool]$runtimeConfigRead
  service_sid_unrestricted = [bool]$sidTypeOk
  agent_root_read_execute = [bool]$agentRootReadExecute
  workspace_modify = [bool]$workspaceModify
  state_modify = [bool]$stateModify
}}
""".strip()


def probe_agent_service_readiness(
    vm_name: str,
    credential: PowerShellDirectCredential,
    config: AgentServiceConfig,
    *,
    package_manifest: AgentPackageManifest,
    runtime_config: AgentServiceRuntimeConfig,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    return run_vm_powershell_json(
        vm_name,
        credential,
        build_agent_service_readiness_script(
            config,
            package_manifest=package_manifest,
            runtime_config=runtime_config,
        ),
        timeout_seconds=timeout_seconds,
    )


def require_agent_service_ready(result: dict[str, object]) -> None:
    if not bool(result.get("service_ready", False)):
        raise RuntimeError("HMS Agent Windows service readiness contract failed")
