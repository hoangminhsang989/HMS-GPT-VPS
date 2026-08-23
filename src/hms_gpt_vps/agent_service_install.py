from __future__ import annotations

from dataclasses import dataclass

from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


@dataclass(frozen=True)
class AgentServiceConfig:
    service_name: str = "HMSAgent"
    display_name: str = "HMS GPT VPS Agent"
    binary_path: str = r"C:\ProgramData\HMS-GPT-VPS\Agent\hms-agent.exe"
    workspace_path: str = r"C:\HMS-Workspace"
    runtime_path: str = r"C:\ProgramData\HMS-GPT-VPS"
    state_path: str = r"C:\ProgramData\HMS-GPT-VPS\State"

    def validate(self) -> None:
        if not self.service_name.strip():
            raise ValueError("service_name is required")
        if any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in self.service_name):
            raise ValueError("service_name contains unsupported characters")
        if not self.binary_path.strip():
            raise ValueError("binary_path is required")
        if not self.workspace_path.strip():
            raise ValueError("workspace_path is required")
        if not self.state_path.strip():
            raise ValueError("state_path is required")


def build_agent_service_install_script(
    config: AgentServiceConfig,
    *,
    expected_sha256: str,
) -> str:
    """Install/reconcile HMS Agent as LocalService plus per-service SID.

    The copied agent executable is hash-verified inside the guest before SCM is
    modified. Workspace/state Modify permission is granted only to the service
    SID; the executable directory remains read/execute for that SID.
    """
    config.validate()
    if len(expected_sha256) != 64:
        raise ValueError("expected_sha256 must contain 64 hex characters")
    try:
        int(expected_sha256, 16)
    except ValueError as exc:
        raise ValueError("expected_sha256 must be hexadecimal") from exc

    service_name = ps_literal(config.service_name)
    display_name = ps_literal(config.display_name)
    binary_path = ps_literal(config.binary_path)
    workspace = ps_literal(config.workspace_path)
    runtime = ps_literal(config.runtime_path)
    state = ps_literal(config.state_path)
    expected_hash = ps_literal(expected_sha256.lower())

    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$displayName = {display_name}
$binaryPath = {binary_path}
$workspace = {workspace}
$runtime = {runtime}
$statePath = {state}
$expectedHash = {expected_hash}
$servicePrincipal = "NT SERVICE\\$serviceName"

if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {{
  throw 'HMS Agent executable is missing inside guest'
}}
$actualHash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {{
  throw 'HMS Agent executable SHA-256 mismatch inside guest'
}}

foreach ($path in @($workspace, $runtime, $statePath)) {{
  if (-not (Test-Path -LiteralPath $path)) {{
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }}
}}

$quotedBinary = '"' + $binaryPath + '" service'
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $existing) {{
  & sc.exe create $serviceName 'binPath=' $quotedBinary 'start=' 'auto' 'obj=' 'NT AUTHORITY\\LocalService' 'DisplayName=' $displayName | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'sc.exe create HMS Agent failed' }}
}} else {{
  $wmi = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
  if ($wmi.PathName -ne $quotedBinary) {{
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

$agentRoot = Split-Path -Parent $binaryPath
foreach ($path in @($agentRoot, $workspace, $statePath)) {{
  if (-not (Test-Path -LiteralPath $path)) {{ throw "Required HMS path missing: $path" }}
}}

& icacls.exe $agentRoot '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${{servicePrincipal}}:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to protect HMS Agent binary directory ACL' }}

foreach ($path in @($workspace, $statePath)) {{
  & icacls.exe $path '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${{servicePrincipal}}:(OI)(CI)M" | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw "Failed to grant service SID on $path" }}
}}

$sidInfo = (& sc.exe qsidtype $serviceName 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $sidInfo -notmatch 'UNRESTRICTED') {{
  throw 'HMS Agent per-service SID verification failed'
}}

$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne 'Running') {{
  Start-Service -Name $serviceName -ErrorAction Stop
}}
$service = Get-Service -Name $serviceName -ErrorAction Stop
$wmi = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop

[pscustomobject]@{{
  ready = [bool]($service.Status -eq 'Running')
  service_name = $serviceName
  status = $service.Status.ToString()
  start_mode = $wmi.StartMode
  start_name = $wmi.StartName
  binary_path = $binaryPath
  binary_sha256 = $actualHash
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
    expected_sha256: str,
    timeout_seconds: int = 180,
) -> dict[str, object]:
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_agent_service_install_script(config, expected_sha256=expected_sha256),
        timeout_seconds=timeout_seconds,
    )
    if not bool(result.get("ready", False)):
        raise RuntimeError("HMS Agent service postcondition failed")
    return result
