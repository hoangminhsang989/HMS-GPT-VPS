from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
import uuid

from .agent_bridge_production_tls import qualify_agent_bridge_production_tls
from .bridge_host_deployment_transaction import derive_hms_bridge_service_sid
from .bridge_package import (
    BridgePackageManifest,
    load_bridge_package_manifest,
    require_bridge_windows_amd64_pe,
    verify_bridge_package,
)
from .bridge_package_deployment import (
    DEFAULT_BRIDGE_BINARY_PATH,
    DEFAULT_BRIDGE_PACKAGE_MANIFEST_PATH,
    DEFAULT_BRIDGE_PACKAGE_ROOT,
)
from .bridge_service_config_storage import load_protected_bridge_service_runtime_config
from .bridge_service_identity import HMS_BRIDGE_SERVICE_ACCOUNT, HMS_BRIDGE_SERVICE_NAME
from .bridge_service_provisioning_identity import prove_hms_bridge_provisioning_identity
from .bridge_service_runtime_config import BridgeServiceRuntimeConfig
from .powershell import ps_literal, run_powershell_json
from .powershell_direct import PowerShellDirectCredential


_START_KEYS = frozenset(
    {
        "ready",
        "service_name",
        "service_sid",
        "service_state",
        "service_start_mode",
        "service_start_name",
        "service_path_name",
        "process_id",
        "binary_sha256",
        "tls_listener_ready",
        "tls_listener_host",
        "tls_listener_port",
        "mcp_listener_ready",
        "mcp_listener_host",
        "mcp_listener_port",
        "exit_code",
        "service_specific_exit_code",
    }
)
_STOP_KEYS = frozenset(
    {
        "ready",
        "service_name",
        "service_sid",
        "service_state",
        "service_start_mode",
        "service_start_name",
        "service_path_name",
        "process_id",
        "tls_listener_absent",
        "mcp_listener_absent",
    }
)


class BridgeActivationQualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class BridgeActivationQualificationRequest:
    guest_credential: PowerShellDirectCredential = field(repr=False)
    trust_root_certificate_pem: bytes = field(repr=False)

    def validate(self) -> None:
        if not isinstance(self.guest_credential, PowerShellDirectCredential):
            raise TypeError("guest_credential must be a PowerShellDirectCredential")
        self.guest_credential.validate()
        if (
            not isinstance(self.trust_root_certificate_pem, bytes)
            or not self.trust_root_certificate_pem
        ):
            raise TypeError("trust_root_certificate_pem must be non-empty bytes")


def _windows_path(value: Path | str) -> str:
    return str(PureWindowsPath(str(value)))


def _build_service_start_script(
    *,
    service_sid: str,
    binary_sha256: str,
    tls_host: str,
    tls_port: int,
    mcp_port: int,
) -> str:
    service_name = ps_literal(HMS_BRIDGE_SERVICE_NAME)
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    expected_sid = ps_literal(service_sid)
    binary_path = ps_literal(_windows_path(DEFAULT_BRIDGE_BINARY_PATH))
    binary_sha = ps_literal(binary_sha256)
    tls_host_literal = ps_literal(tls_host)
    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$serviceAccount = {service_account}
$expectedServiceSid = {expected_sid}
$binaryPath = [System.IO.Path]::GetFullPath({binary_path})
$expectedPathName = '"' + $binaryPath + '" service'
$expectedBinarySha = {binary_sha}
$tlsHost = {tls_host_literal}
$tlsPort = [int]{tls_port}
$mcpHost = '127.0.0.1'
$mcpPort = [int]{mcp_port}

function Get-ExactService {{
  $rows = @(Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
  if ($rows.Count -ne 1) {{ throw 'Expected exactly one HMSBridge service' }}
  $svc = $rows[0]
  if ([string]$svc.StartName -ine $serviceAccount) {{ throw 'HMSBridge service account differs' }}
  if ([string]$svc.StartMode -ne 'Manual') {{ throw 'HMSBridge must remain Manual during qualification' }}
  if ([string]$svc.PathName -ne $expectedPathName) {{ throw 'HMSBridge service command differs' }}
  $sid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
  if ($sid -ne $expectedServiceSid) {{ throw 'HMSBridge service SID differs' }}
  $sha = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($sha -ne $expectedBinarySha) {{ throw 'HMSBridge binary SHA-256 differs' }}
  return $svc
}}
function Get-Listener([string]$address, [int]$port, [uint32]$pid) {{
  $rows = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Where-Object {{
    $_.LocalAddress -eq $address -and [uint32]$_.OwningProcess -eq $pid
  }})
  if ($rows.Count -ne 1) {{ throw "Expected exactly one qualified listener at $address`:$port" }}
  return $rows[0]
}}

$service = Get-ExactService
if ([string]$service.State -ne 'Stopped' -or [uint32]$service.ProcessId -ne 0) {{
  throw 'HMSBridge must be fully Stopped before qualification start'
}}
$existingTls = @(Get-NetTCPConnection -State Listen -LocalPort $tlsPort -ErrorAction SilentlyContinue | Where-Object {{ $_.LocalAddress -eq $tlsHost }})
$existingMcp = @(Get-NetTCPConnection -State Listen -LocalPort $mcpPort -ErrorAction SilentlyContinue | Where-Object {{ $_.LocalAddress -eq $mcpHost }})
if ($existingTls.Count -ne 0 -or $existingMcp.Count -ne 0) {{ throw 'Bridge qualification ports already have listeners before service start' }}

$started = $false
try {{
  Start-Service -Name $serviceName -ErrorAction Stop -WarningAction SilentlyContinue
  $started = $true
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  do {{
    Start-Sleep -Milliseconds 200
    $service = Get-ExactService
    if ([string]$service.State -eq 'Running') {{ break }}
    if ([string]$service.State -eq 'Stopped') {{
      throw ('HMSBridge returned to Stopped during startup; ExitCode=' + [string]$service.ExitCode + '; ServiceSpecificExitCode=' + [string]$service.ServiceSpecificExitCode)
    }}
  }} while ([DateTime]::UtcNow -lt $deadline)
  if ([string]$service.State -ne 'Running') {{ throw 'HMSBridge did not reach Running before startup timeout' }}
  if ([uint32]$service.ProcessId -eq 0) {{ throw 'Running HMSBridge has no process id' }}
  $pid = [uint32]$service.ProcessId
  Get-Listener $tlsHost $tlsPort $pid | Out-Null
  Get-Listener $mcpHost $mcpPort $pid | Out-Null
  Start-Sleep -Milliseconds 500
  $service = Get-ExactService
  if ([string]$service.State -ne 'Running' -or [uint32]$service.ProcessId -ne $pid) {{
    throw 'HMSBridge did not remain stably Running after listener readiness'
  }}
  [pscustomobject]@{{
    ready = $true
    service_name = [string]$service.Name
    service_sid = [string]$expectedServiceSid
    service_state = [string]$service.State
    service_start_mode = [string]$service.StartMode
    service_start_name = [string]$service.StartName
    service_path_name = [string]$service.PathName
    process_id = [uint32]$service.ProcessId
    binary_sha256 = [string]$expectedBinarySha
    tls_listener_ready = $true
    tls_listener_host = [string]$tlsHost
    tls_listener_port = [int]$tlsPort
    mcp_listener_ready = $true
    mcp_listener_host = [string]$mcpHost
    mcp_listener_port = [int]$mcpPort
    exit_code = [uint32]$service.ExitCode
    service_specific_exit_code = [uint32]$service.ServiceSpecificExitCode
  }}
}} catch {{
  if ($started) {{
    try {{ Stop-Service -Name $serviceName -Force -ErrorAction Stop -WarningAction SilentlyContinue }} catch {{ }}
  }}
  throw
}}
""".strip()


def _build_service_stop_script(
    *,
    service_sid: str,
    tls_host: str,
    tls_port: int,
    mcp_port: int,
) -> str:
    service_name = ps_literal(HMS_BRIDGE_SERVICE_NAME)
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    expected_sid = ps_literal(service_sid)
    binary_path = ps_literal(_windows_path(DEFAULT_BRIDGE_BINARY_PATH))
    tls_host_literal = ps_literal(tls_host)
    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$serviceAccount = {service_account}
$expectedServiceSid = {expected_sid}
$binaryPath = [System.IO.Path]::GetFullPath({binary_path})
$expectedPathName = '"' + $binaryPath + '" service'
$tlsHost = {tls_host_literal}
$tlsPort = [int]{tls_port}
$mcpHost = '127.0.0.1'
$mcpPort = [int]{mcp_port}
function Get-ExactService {{
  $rows = @(Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
  if ($rows.Count -ne 1) {{ throw 'Expected exactly one HMSBridge service during stop' }}
  $svc = $rows[0]
  if ([string]$svc.StartName -ine $serviceAccount -or [string]$svc.StartMode -ne 'Manual' -or [string]$svc.PathName -ne $expectedPathName) {{
    throw 'HMSBridge service authority drifted before stop'
  }}
  $sid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
  if ($sid -ne $expectedServiceSid) {{ throw 'HMSBridge SID drifted before stop' }}
  return $svc
}}
$service = Get-ExactService
if ([string]$service.State -ne 'Stopped') {{
  Stop-Service -Name $serviceName -Force -ErrorAction Stop -WarningAction SilentlyContinue
}}
$deadline = [DateTime]::UtcNow.AddSeconds(45)
do {{
  Start-Sleep -Milliseconds 200
  $service = Get-ExactService
  if ([string]$service.State -eq 'Stopped' -and [uint32]$service.ProcessId -eq 0) {{ break }}
}} while ([DateTime]::UtcNow -lt $deadline)
if ([string]$service.State -ne 'Stopped' -or [uint32]$service.ProcessId -ne 0) {{ throw 'HMSBridge did not fully stop' }}
$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {{
  $tls = @(Get-NetTCPConnection -State Listen -LocalPort $tlsPort -ErrorAction SilentlyContinue | Where-Object {{ $_.LocalAddress -eq $tlsHost }})
  $mcp = @(Get-NetTCPConnection -State Listen -LocalPort $mcpPort -ErrorAction SilentlyContinue | Where-Object {{ $_.LocalAddress -eq $mcpHost }})
  if ($tls.Count -eq 0 -and $mcp.Count -eq 0) {{ break }}
  Start-Sleep -Milliseconds 200
}} while ([DateTime]::UtcNow -lt $deadline)
if ($tls.Count -ne 0 -or $mcp.Count -ne 0) {{ throw 'Bridge listeners remained after HMSBridge stop' }}
[pscustomobject]@{{
  ready = $true
  service_name = [string]$service.Name
  service_sid = [string]$expectedServiceSid
  service_state = [string]$service.State
  service_start_mode = [string]$service.StartMode
  service_start_name = [string]$service.StartName
  service_path_name = [string]$service.PathName
  process_id = [uint32]$service.ProcessId
  tls_listener_absent = $true
  mcp_listener_absent = $true
}}
""".strip()


def _validate_start_evidence(
    result: dict[str, object],
    *,
    service_sid: str,
    binary_sha256: str,
    tls_host: str,
    tls_port: int,
    mcp_port: int,
) -> dict[str, object]:
    if frozenset(result) != _START_KEYS:
        raise BridgeActivationQualificationError("activation start evidence schema is invalid")
    expected = {
        "ready": True,
        "service_name": HMS_BRIDGE_SERVICE_NAME,
        "service_sid": service_sid,
        "service_state": "Running",
        "service_start_mode": "Manual",
        "binary_sha256": binary_sha256,
        "tls_listener_ready": True,
        "tls_listener_host": tls_host,
        "tls_listener_port": tls_port,
        "mcp_listener_ready": True,
        "mcp_listener_host": "127.0.0.1",
        "mcp_listener_port": mcp_port,
    }
    for key, wanted in expected.items():
        if result.get(key) != wanted:
            raise BridgeActivationQualificationError(f"activation start evidence differs: {key}")
    start_name = result.get("service_start_name")
    if not isinstance(start_name, str) or start_name.casefold() != HMS_BRIDGE_SERVICE_ACCOUNT.casefold():
        raise BridgeActivationQualificationError("activation service account differs")
    expected_path = f'"{_windows_path(DEFAULT_BRIDGE_BINARY_PATH)}" service'
    path_name = result.get("service_path_name")
    if not isinstance(path_name, str) or path_name.casefold() != expected_path.casefold():
        raise BridgeActivationQualificationError("activation service command differs")
    pid = result.get("process_id")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise BridgeActivationQualificationError("activation service process id is invalid")
    for key in ("exit_code", "service_specific_exit_code"):
        value = result.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value != 0:
            raise BridgeActivationQualificationError(f"activation service returned nonzero {key}")
    return dict(result)


def _validate_stop_evidence(result: dict[str, object], *, service_sid: str) -> dict[str, object]:
    if frozenset(result) != _STOP_KEYS:
        raise BridgeActivationQualificationError("activation stop evidence schema is invalid")
    expected = {
        "ready": True,
        "service_name": HMS_BRIDGE_SERVICE_NAME,
        "service_sid": service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "process_id": 0,
        "tls_listener_absent": True,
        "mcp_listener_absent": True,
    }
    for key, wanted in expected.items():
        if result.get(key) != wanted:
            raise BridgeActivationQualificationError(f"activation stop evidence differs: {key}")
    start_name = result.get("service_start_name")
    if not isinstance(start_name, str) or start_name.casefold() != HMS_BRIDGE_SERVICE_ACCOUNT.casefold():
        raise BridgeActivationQualificationError("activation stopped service account differs")
    expected_path = f'"{_windows_path(DEFAULT_BRIDGE_BINARY_PATH)}" service'
    path_name = result.get("service_path_name")
    if not isinstance(path_name, str) or path_name.casefold() != expected_path.casefold():
        raise BridgeActivationQualificationError("activation stopped service command differs")
    return dict(result)


def _load_and_verify_package() -> BridgePackageManifest:
    manifest = load_bridge_package_manifest(DEFAULT_BRIDGE_PACKAGE_MANIFEST_PATH)
    verify_bridge_package(DEFAULT_BRIDGE_PACKAGE_ROOT, manifest)
    require_bridge_windows_amd64_pe(DEFAULT_BRIDGE_BINARY_PATH)
    return manifest


def start_hms_bridge_for_qualification(
    runtime_config: BridgeServiceRuntimeConfig,
    manifest: BridgePackageManifest,
    service_sid: str,
) -> dict[str, object]:
    runtime = runtime_config.to_runtime_config(service_sid)
    script = _build_service_start_script(
        service_sid=service_sid,
        binary_sha256=manifest.sha256.lower(),
        tls_host=runtime.tls.firewall.network.gateway,
        tls_port=runtime.tls.firewall.port,
        mcp_port=runtime.production.mcp.port,
    )
    try:
        result = run_powershell_json(script, timeout_seconds=90)
        return _validate_start_evidence(
            result,
            service_sid=service_sid,
            binary_sha256=manifest.sha256.lower(),
            tls_host=runtime.tls.firewall.network.gateway,
            tls_port=runtime.tls.firewall.port,
            mcp_port=runtime.production.mcp.port,
        )
    except BaseException as start_exc:
        try:
            stop_hms_bridge_after_qualification(runtime_config, service_sid)
        except BaseException as stop_exc:
            raise BridgeActivationQualificationError(
                "HMSBridge startup proof failed and emergency stop also failed"
            ) from stop_exc
        raise start_exc


def stop_hms_bridge_after_qualification(
    runtime_config: BridgeServiceRuntimeConfig,
    service_sid: str,
) -> dict[str, object]:
    runtime = runtime_config.to_runtime_config(service_sid)
    result = run_powershell_json(
        _build_service_stop_script(
            service_sid=service_sid,
            tls_host=runtime.tls.firewall.network.gateway,
            tls_port=runtime.tls.firewall.port,
            mcp_port=runtime.production.mcp.port,
        ),
        timeout_seconds=90,
    )
    return _validate_stop_evidence(result, service_sid=service_sid)


def qualify_hms_bridge_activation_probe(
    request: BridgeActivationQualificationRequest,
) -> dict[str, object]:
    """Start reviewed HMSBridge, prove TLS/MCP readiness, qualify guest TLS, then stop."""

    request.validate()
    service_sid = derive_hms_bridge_service_sid()
    config = load_protected_bridge_service_runtime_config()
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise BridgeActivationQualificationError("protected runtime config type is invalid")
    config.validate()
    runtime = config.to_runtime_config(service_sid)
    manifest = _load_and_verify_package()

    pre = prove_hms_bridge_provisioning_identity()
    if (
        pre.get("service_sid") != service_sid
        or pre.get("service_state") != "Stopped"
        or pre.get("service_start_mode") != "Manual"
    ):
        raise BridgeActivationQualificationError("HMSBridge is not exact Stopped/Manual before activation")

    started = False
    qualification: dict[str, object] | None = None
    start_evidence: dict[str, object] | None = None
    stop_evidence: dict[str, object] | None = None
    primary_error: BaseException | None = None
    try:
        start_evidence = start_hms_bridge_for_qualification(config, manifest, service_sid)
        started = True
        qualification = qualify_agent_bridge_production_tls(
            runtime.tls,
            request.guest_credential,
            request.trust_root_certificate_pem,
        )
        if qualification.get("live_managed_guest_tls_proven") is not True:
            raise BridgeActivationQualificationError("managed-guest TLS qualification did not pass")
        if qualification.get("server_certificate_sha256") != runtime.tls.material.certificate_der_sha256:
            raise BridgeActivationQualificationError("managed guest observed the wrong TLS certificate")
        expected_vm_id = str(uuid.UUID(runtime.tls.guest.vm_id)).lower()
        observed_vm_id = qualification.get("vm_id")
        if not isinstance(observed_vm_id, str) or str(uuid.UUID(observed_vm_id)).lower() != expected_vm_id:
            raise BridgeActivationQualificationError("managed-guest TLS proof VMId differs")
        if qualification.get("bridge_origin") != runtime.tls.guest.bridge_origin:
            raise BridgeActivationQualificationError("managed-guest TLS proof origin differs")
    except BaseException as exc:
        primary_error = exc
    finally:
        if started:
            try:
                stop_evidence = stop_hms_bridge_after_qualification(config, service_sid)
            except BaseException as stop_exc:
                if primary_error is None:
                    primary_error = stop_exc
                else:
                    raise BridgeActivationQualificationError(
                        "qualification failed and HMSBridge stop also failed"
                    ) from stop_exc
    if primary_error is not None:
        raise primary_error
    if start_evidence is None or stop_evidence is None or qualification is None:
        raise BridgeActivationQualificationError("activation qualification evidence is incomplete")

    post = prove_hms_bridge_provisioning_identity()
    if (
        post.get("service_sid") != service_sid
        or post.get("service_state") != "Stopped"
        or post.get("service_start_mode") != "Manual"
    ):
        raise BridgeActivationQualificationError("HMSBridge did not return to exact Stopped/Manual")

    return {
        "ready": True,
        "status": "QUALIFIED_STOPPED",
        "service_sid": service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "service_runtime_ready_proven": True,
        "tls_listener_ready_during_probe": True,
        "mcp_listener_ready_during_probe": True,
        "runtime_process_id": start_evidence["process_id"],
        "live_managed_guest_tls_proven": True,
        "server_certificate_sha256": qualification["server_certificate_sha256"],
        "vm_id": qualification["vm_id"],
        "bridge_origin": qualification["bridge_origin"],
        "listeners_absent_after_stop": True,
        "authenticated_agent_transport_proven": False,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
