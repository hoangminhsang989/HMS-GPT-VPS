from __future__ import annotations

from .agent_service_install import AgentServiceConfig
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


def build_agent_service_readiness_script(
    config: AgentServiceConfig,
    *,
    expected_sha256: str,
) -> str:
    """Build a read-only guest probe for the Windows service bootstrap boundary.

    This proves SCM configuration, binary integrity, per-service SID and the
    minimum filesystem ACL contract. It deliberately does not claim application
    protocol health; `/healthz` belongs to the Agent implementation itself.
    """
    config.validate()
    if len(expected_sha256) != 64:
        raise ValueError("expected_sha256 must contain 64 hex characters")
    try:
        int(expected_sha256, 16)
    except ValueError as exc:
        raise ValueError("expected_sha256 must be hexadecimal") from exc

    service_name = ps_literal(config.service_name)
    binary_path = ps_literal(config.binary_path)
    workspace = ps_literal(config.workspace_path)
    state_path = ps_literal(config.state_path)
    expected_hash = ps_literal(expected_sha256.lower())

    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$binaryPath = {binary_path}
$workspace = {workspace}
$statePath = {state_path}
$expectedHash = {expected_hash}
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
$agentRootReadExecute = Test-HmsAclRight $agentRoot ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
$workspaceModify = Test-HmsAclRight $workspace ([System.Security.AccessControl.FileSystemRights]::Modify)
$stateModify = Test-HmsAclRight $statePath ([System.Security.AccessControl.FileSystemRights]::Modify)

$serviceReady = [bool](
  $serviceExists -and
  $serviceRunning -and
  $startNameOk -and
  $commandOk -and
  $binaryExists -and
  $binaryHashOk -and
  $sidTypeOk -and
  $agentRootReadExecute -and
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
    timeout_seconds: int = 90,
) -> dict[str, object]:
    return run_vm_powershell_json(
        vm_name,
        credential,
        build_agent_service_readiness_script(config, expected_sha256=expected_sha256),
        timeout_seconds=timeout_seconds,
    )


def require_agent_service_ready(result: dict[str, object]) -> None:
    if not bool(result.get("service_ready", False)):
        raise RuntimeError("HMS Agent Windows service readiness contract failed")
