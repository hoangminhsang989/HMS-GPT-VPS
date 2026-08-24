from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import PureWindowsPath

from .agent_package import AgentPackageManifest
from .agent_package_manifest_artifact import (
    canonical_agent_package_manifest_sha256,
    canonical_agent_package_manifest_size,
    managed_agent_package_manifest_path,
)
from .agent_package_powershell import POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION
from .agent_service_runtime_config import AgentServiceRuntimeConfig
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


@dataclass(frozen=True)
class AgentServiceConfig:
    service_name: str = "HMSAgent"
    display_name: str = "HMS GPT VPS Agent"
    agent_root_path: str = r"C:\ProgramData\HMS-GPT-VPS\Agent"
    package_path: str = r"C:\ProgramData\HMS-GPT-VPS\Agent\package"
    binary_path: str = r"C:\ProgramData\HMS-GPT-VPS\Agent\package\hms-agent.exe"
    runtime_config_path: str = r"C:\ProgramData\HMS-GPT-VPS\Agent\agent-runtime.json"
    workspace_path: str = r"C:\HMS-Workspace"
    runtime_path: str = r"C:\ProgramData\HMS-GPT-VPS"
    state_path: str = r"C:\ProgramData\HMS-GPT-VPS\State"

    def validate(self) -> None:
        if not self.service_name.strip():
            raise ValueError("service_name is required")
        if any(
            char
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for char in self.service_name
        ):
            raise ValueError("service_name contains unsupported characters")
        for name, value in (
            ("agent_root_path", self.agent_root_path),
            ("package_path", self.package_path),
            ("binary_path", self.binary_path),
            ("runtime_config_path", self.runtime_config_path),
            ("workspace_path", self.workspace_path),
            ("runtime_path", self.runtime_path),
            ("state_path", self.state_path),
        ):
            if not value.strip():
                raise ValueError(f"{name} is required")
            if not PureWindowsPath(value).is_absolute():
                raise ValueError(f"{name} must be an absolute Windows path")

        agent_root = PureWindowsPath(self.agent_root_path)
        package_root = PureWindowsPath(self.package_path)
        binary = PureWindowsPath(self.binary_path)
        runtime_config = PureWindowsPath(self.runtime_config_path)
        runtime_root = PureWindowsPath(self.runtime_path)
        if str(package_root.parent).casefold() != str(agent_root).casefold():
            raise ValueError("package_path must be a direct child of protected Agent root")
        if str(binary.parent).casefold() != str(package_root).casefold():
            raise ValueError("binary_path must be the entrypoint inside package_path")
        if binary.name.casefold() != "hms-agent.exe":
            raise ValueError("binary_path must end with hms-agent.exe")
        if str(runtime_config.parent).casefold() != str(agent_root).casefold():
            raise ValueError("runtime_config_path must be inside protected Agent root")
        if str(agent_root.parent).casefold() != str(runtime_root).casefold():
            raise ValueError("protected Agent root must be inside runtime_path")
        if runtime_config.name.casefold() == binary.name.casefold():
            raise ValueError("runtime config must not replace the Agent executable")


def _same_windows_path(left: str, right: str) -> bool:
    return str(PureWindowsPath(left)).casefold() == str(PureWindowsPath(right)).casefold()


def _validate_runtime_config_alignment(
    service: AgentServiceConfig,
    runtime: AgentServiceRuntimeConfig,
) -> None:
    runtime.validate()
    if not _same_windows_path(runtime.workspace_root, service.workspace_path):
        raise ValueError("runtime config workspace_root conflicts with service ACL target")
    if not _same_windows_path(runtime.state_root, service.state_path):
        raise ValueError("runtime config state_root conflicts with service ACL target")


def build_agent_service_install_script(
    config: AgentServiceConfig,
    *,
    package_manifest: AgentPackageManifest,
    runtime_config: AgentServiceRuntimeConfig,
) -> str:
    """Install/reconcile an exact onedir Agent tree and protected runtime config.

    The canonical manifest artifact and complete package tree are verified before
    any SCM mutation. The manifest is read from the protected guest Agent root,
    so PowerShell Direct command size does not grow with package file count.
    """
    config.validate()
    package_manifest.validate()
    _validate_runtime_config_alignment(config, runtime_config)

    runtime_bytes = runtime_config.to_bytes()
    runtime_config_b64 = base64.b64encode(runtime_bytes).decode("ascii")
    runtime_config_hash = runtime_config.sha256()

    service_name = ps_literal(config.service_name)
    display_name = ps_literal(config.display_name)
    agent_root = ps_literal(config.agent_root_path)
    package_root = ps_literal(config.package_path)
    package_manifest_path = ps_literal(managed_agent_package_manifest_path(config.agent_root_path))
    binary_path = ps_literal(config.binary_path)
    runtime_config_path = ps_literal(config.runtime_config_path)
    workspace = ps_literal(config.workspace_path)
    runtime = ps_literal(config.runtime_path)
    state = ps_literal(config.state_path)
    expected_hash = ps_literal(package_manifest.sha256.lower())
    expected_manifest_hash = ps_literal(canonical_agent_package_manifest_sha256(package_manifest))
    expected_manifest_size = canonical_agent_package_manifest_size(package_manifest)
    expected_config_hash = ps_literal(runtime_config_hash)
    runtime_config_payload = ps_literal(runtime_config_b64)

    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$displayName = {display_name}
$agentRoot = {agent_root}
$packageRoot = {package_root}
$packageManifestPath = {package_manifest_path}
$binaryPath = {binary_path}
$runtimeConfigPath = {runtime_config_path}
$workspace = {workspace}
$runtime = {runtime}
$statePath = {state}
$expectedHash = {expected_hash}
$expectedManifestHash = {expected_manifest_hash}
$expectedManifestSize = [int64]{expected_manifest_size}
$expectedRuntimeConfigHash = {expected_config_hash}
$runtimeConfigPayload = {runtime_config_payload}
$servicePrincipal = "NT SERVICE\\$serviceName"
$expectedQuotedCommand = '"' + $binaryPath + '" service'
$expectedUnquotedCommand = $binaryPath + ' service'

{POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION}

if ((Split-Path -Parent $packageRoot) -ne $agentRoot) {{
  throw 'HMS Agent package root escaped the protected Agent root'
}}
if ((Split-Path -Parent $packageManifestPath) -ne $agentRoot) {{
  throw 'HMS Agent package manifest escaped the protected Agent root'
}}
if ((Split-Path -Parent $binaryPath) -ne $packageRoot) {{
  throw 'HMS Agent executable escaped the package root'
}}
if ((Split-Path -Parent $runtimeConfigPath) -ne $agentRoot) {{
  throw 'HMS Agent runtime config escaped the protected Agent root'
}}
if (-not (Test-Path -LiteralPath $packageManifestPath -PathType Leaf)) {{
  throw 'HMS Agent canonical package manifest is missing inside guest'
}}
$manifestItem = Get-Item -LiteralPath $packageManifestPath -Force -ErrorAction Stop
if (($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMS Agent canonical package manifest must not be a reparse point'
}}
if ([int64]$manifestItem.Length -ne $expectedManifestSize) {{
  throw 'HMS Agent canonical package manifest size mismatch inside guest'
}}
if ((Get-HmsSha256 $packageManifestPath) -ne $expectedManifestHash) {{
  throw 'HMS Agent canonical package manifest SHA-256 mismatch inside guest'
}}
$packageManifestPayload = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($packageManifestPath))
$packageProof = Test-HmsAgentPackageTree $packageRoot $packageManifestPayload
$actualHash = [string]$packageProof.entrypoint_sha256
if ($actualHash -ne $expectedHash) {{
  throw 'HMS Agent entrypoint SHA-256 mismatch inside guest'
}}

foreach ($path in @($workspace, $runtime, $statePath, $agentRoot, $packageRoot)) {{
  if (-not (Test-Path -LiteralPath $path)) {{
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }}
}}

$configChanged = $true
$actualRuntimeConfigHash = $null
if (Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf) {{
  $actualRuntimeConfigHash = Get-HmsSha256 $runtimeConfigPath
  $configChanged = $actualRuntimeConfigHash -ne $expectedRuntimeConfigHash
}}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($configChanged -and $null -ne $existing -and $existing.Status -eq 'Running') {{
  $null = Stop-Service -Name $serviceName -ErrorAction Stop -WarningAction SilentlyContinue
  $null = $existing.WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
    [TimeSpan]::FromSeconds(30)
  )
  $null = $existing.Refresh()
  if ($existing.Status -ne 'Stopped') {{
    throw 'HMS Agent did not stop for runtime config replacement'
  }}
}}

if ($configChanged) {{
  $configBytes = [Convert]::FromBase64String($runtimeConfigPayload)
  $configTemp = $runtimeConfigPath + '.hms-' + [guid]::NewGuid().ToString('N') + '.tmp'
  try {{
    [System.IO.File]::WriteAllBytes($configTemp, $configBytes)
    $tempHash = Get-HmsSha256 $configTemp
    if ($tempHash -ne $expectedRuntimeConfigHash) {{
      throw 'HMS Agent runtime config temp SHA-256 mismatch inside guest'
    }}
    if (Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf) {{
      [System.IO.File]::Replace($configTemp, $runtimeConfigPath, $null, $true)
    }} else {{
      [System.IO.File]::Move($configTemp, $runtimeConfigPath)
    }}
  }} finally {{
    if (Test-Path -LiteralPath $configTemp -PathType Leaf) {{
      Remove-Item -LiteralPath $configTemp -Force -ErrorAction SilentlyContinue
    }}
  }}
}}

if (-not (Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf)) {{
  throw 'HMS Agent runtime config publication failed'
}}
$actualRuntimeConfigHash = Get-HmsSha256 $runtimeConfigPath
if ($actualRuntimeConfigHash -ne $expectedRuntimeConfigHash) {{
  throw 'HMS Agent runtime config SHA-256 mismatch inside guest'
}}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $existing) {{
  & sc.exe create $serviceName 'binPath=' $expectedQuotedCommand 'start=' 'auto' 'obj=' 'NT AUTHORITY\\LocalService' 'DisplayName=' $displayName | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'sc.exe create HMS Agent failed' }}
}} else {{
  $wmi = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
  $commandOk = [bool](
    $wmi.PathName -eq $expectedQuotedCommand -or
    (($binaryPath -notmatch '\\s') -and $wmi.PathName -eq $expectedUnquotedCommand)
  )
  if (-not $commandOk) {{
    throw 'Existing HMS Agent service binary path conflicts with managed configuration'
  }}
  if ($wmi.StartName -ne 'NT AUTHORITY\\LocalService') {{
    throw 'Existing HMS Agent service account conflicts with LocalService baseline'
  }}
}}

& sc.exe sidtype $serviceName unrestricted | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to enable per-service SID' }}
& sc.exe description $serviceName 'HMS isolated guest control agent' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to set HMS Agent service description' }}
& sc.exe failure $serviceName 'reset=' '86400' 'actions=' 'restart/5000/restart/15000/restart/60000' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to configure HMS Agent failure recovery' }}
& sc.exe failureflag $serviceName '1' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to enable HMS Agent non-crash failure recovery' }}

foreach ($path in @($agentRoot, $packageRoot, $packageManifestPath, $workspace, $statePath)) {{
  if (-not (Test-Path -LiteralPath $path)) {{ throw "Required HMS path missing: $path" }}
}}

& icacls.exe $agentRoot '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${{servicePrincipal}}:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to protect HMS Agent package/config directory ACL' }}

foreach ($path in @($workspace, $statePath)) {{
  & icacls.exe $path '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${{servicePrincipal}}:(OI)(CI)M" | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw "Failed to grant service SID on $path" }}
}}

$sidInfo = (& sc.exe qsidtype $serviceName 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $sidInfo -notmatch 'UNRESTRICTED') {{
  throw 'HMS Agent per-service SID verification failed'
}}

if ((Get-HmsSha256 $packageManifestPath) -ne $expectedManifestHash) {{
  throw 'HMS Agent canonical package manifest changed after ACL reconciliation'
}}
$packageManifestPayload = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($packageManifestPath))
$packageProof = Test-HmsAgentPackageTree $packageRoot $packageManifestPayload
if ([string]$packageProof.entrypoint_sha256 -ne $expectedHash) {{
  throw 'HMS Agent package changed after ACL reconciliation'
}}

$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne 'Running') {{
  $null = Start-Service -Name $serviceName -ErrorAction Stop -WarningAction SilentlyContinue
}}
$service = Get-Service -Name $serviceName -ErrorAction Stop
$wmi = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop

[pscustomobject]@{{
  ready = [bool]($service.Status -eq 'Running')
  service_name = $serviceName
  status = $service.Status.ToString()
  start_mode = $wmi.StartMode
  start_name = $wmi.StartName
  agent_root = $agentRoot
  package_root = $packageRoot
  package_manifest_path = $packageManifestPath
  package_manifest_sha256 = $expectedManifestHash
  package_file_count = [int]$packageProof.file_count
  package_total_size = [int64]$packageProof.total_size
  binary_path = $binaryPath
  binary_sha256 = [string]$packageProof.entrypoint_sha256
  runtime_config_path = $runtimeConfigPath
  runtime_config_sha256 = $actualRuntimeConfigHash
  runtime_config_changed = [bool]$configChanged
  service_sid_type = 'UNRESTRICTED'
  workspace = $workspace
  state_path = $statePath
}}
""".strip()


def install_agent_service(
    vm_name: str,
    credential: PowerShellDirectCredential,
    config: AgentServiceConfig,
    *,
    package_manifest: AgentPackageManifest,
    runtime_config: AgentServiceRuntimeConfig,
    timeout_seconds: int = 180,
) -> dict[str, object]:
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_agent_service_install_script(
            config,
            package_manifest=package_manifest,
            runtime_config=runtime_config,
        ),
        timeout_seconds=timeout_seconds,
    )
    if not bool(result.get("ready", False)):
        raise RuntimeError("HMS Agent service postcondition failed")
    if str(result.get("package_manifest_sha256", "")).lower() != canonical_agent_package_manifest_sha256(package_manifest):
        raise RuntimeError("HMS Agent package manifest postcondition failed")
    if str(result.get("runtime_config_sha256", "")).lower() != runtime_config.sha256():
        raise RuntimeError("HMS Agent runtime config postcondition failed")
    if int(result.get("package_file_count", 0)) != package_manifest.file_count:
        raise RuntimeError("HMS Agent package file-count postcondition failed")
    if int(result.get("package_total_size", 0)) != package_manifest.total_size:
        raise RuntimeError("HMS Agent package size postcondition failed")
    if str(result.get("binary_sha256", "")).lower() != package_manifest.sha256.lower():
        raise RuntimeError("HMS Agent entrypoint postcondition failed")
    return result
