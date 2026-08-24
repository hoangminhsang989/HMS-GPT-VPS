from __future__ import annotations

from pathlib import PureWindowsPath

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
    expected_sha256: str,
    runtime_config: AgentServiceRuntimeConfig,
) -> str:
    """Build a read-only guest probe for the Windows service bootstrap boundary.

    This proves SCM configuration, binary integrity, the exact protected runtime
    config, per-service SID and the minimum filesystem ACL contract. It still
    leaves application protocol health to the separate `/healthz` gate.
    """
    config.validate()
    _validate_runtime_alignment(config, runtime_config)
    if len(expected_sha256) != 64:
        raise ValueError("expected_sha256 must contain 64 hex characters")
    try:
        int(expected_sha256, 16)
    except ValueError as exc:
        raise ValueError("expected_sha256 must be hexadecimal") from exc

    service_name = ps_literal(config.service_name)
    binary_path = ps_literal(config.binary_path)
    runtime_config_path = ps_literal(config.runtime_config_path)
    workspace = ps_literal(config.workspace_path)
    state_path = ps_literal(config.state_path)
    expected_hash = ps_literal(expected_sha256.lower())
    expected_runtime_config_hash = ps_literal(runtime_config.sha256())

    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$binaryPath = {binary_path}
$runtimeConfigPath = {runtime_config_path}
$workspace = {workspace}
$statePath = {state_path}
$expectedHash = {expected_hash}
$expectedRuntimeConfigHash = {expected_runtime_config_hash}
$servicePrincipal = "NT SERVICE\\$serviceName"
$expectedCommand = '"' + $binaryPath + '" service'

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$serviceExists = $null -ne $service
$serviceRunning = $serviceExists -and $service.Status -eq 'Running'

$startNameOk = $false
$commandOk = $false
if ($serviceExists) {{
  $cim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
  $startNameOk = $cim.StartName -eq 'NT AUTHORITY\\LocalService'
  $commandOk = $cim.PathName -eq $expectedCommand
}}

$binaryExists = Test-Path -LiteralPath $binaryPath -PathType Leaf
$binaryHashOk = $false
$actualHash = $null
if ($binaryExists) {{
  $actualHash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $binaryHashOk = $actualHash -eq $expectedHash
}}

$runtimeConfigExists = Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf
$runtimeConfigHashOk = $false
$actualRuntimeConfigHash = $null
if ($runtimeConfigExists) {{
  $actualRuntimeConfigHash = (Get-FileHash -LiteralPath $runtimeConfigPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
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

function Test-HmsAclRight([string]$Path, [System.Security.AccessControl.FileSystemRights]$Required) {{
  if ($null -eq $serviceSid -or -not (Test-Path -LiteralPath $Path)) {{ return $false }}
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $rules = $acl.GetAccessRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
  )
  foreach ($rule in $rules) {{
    if (
      $rule.IdentityReference -eq $serviceSid -and
      $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      (($rule.FileSystemRights -band $Required) -eq $Required)
    ) {{ return $true }}
  }}
  return $false
}}

$agentRoot = Split-Path -Parent $binaryPath
$runtimeConfigInAgentRoot = (Split-Path -Parent $runtimeConfigPath) -eq $agentRoot
$agentRootReadExecute = Test-HmsAclRight $agentRoot ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
$runtimeConfigRead = Test-HmsAclRight $runtimeConfigPath ([System.Security.AccessControl.FileSystemRights]::Read)
$workspaceModify = Test-HmsAclRight $workspace ([System.Security.AccessControl.FileSystemRights]::Modify)
$stateModify = Test-HmsAclRight $statePath ([System.Security.AccessControl.FileSystemRights]::Modify)

$serviceReady = [bool](
  $serviceExists -and
  $serviceRunning -and
  $startNameOk -and
  $commandOk -and
  $binaryExists -and
  $binaryHashOk -and
  $runtimeConfigExists -and
  $runtimeConfigHashOk -and
  $runtimeConfigInAgentRoot -and
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
  binary_exists = [bool]$binaryExists
  binary_sha256_ok = [bool]$binaryHashOk
  binary_sha256 = $actualHash
  runtime_config_exists = [bool]$runtimeConfigExists
  runtime_config_sha256_ok = [bool]$runtimeConfigHashOk
  runtime_config_sha256 = $actualRuntimeConfigHash
  runtime_config_in_agent_root = [bool]$runtimeConfigInAgentRoot
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
    expected_sha256: str,
    runtime_config: AgentServiceRuntimeConfig,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    return run_vm_powershell_json(
        vm_name,
        credential,
        build_agent_service_readiness_script(
            config,
            expected_sha256=expected_sha256,
            runtime_config=runtime_config,
        ),
        timeout_seconds=timeout_seconds,
    )


def require_agent_service_ready(result: dict[str, object]) -> None:
    if not bool(result.get("service_ready", False)):
        raise RuntimeError("HMS Agent Windows service readiness contract failed")
