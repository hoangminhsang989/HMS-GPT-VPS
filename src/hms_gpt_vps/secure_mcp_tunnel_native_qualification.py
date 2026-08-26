from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import secrets
from urllib.parse import urlsplit

from .bridge_runtime_layout_provisioning import DEFAULT_BRIDGE_RUNTIME_ROOT
from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    HMS_BRIDGE_SERVICE_NAME,
    require_hms_bridge_service_sid,
)
from .bridge_service_secret_storage import (
    BridgeServiceSecretStorageConfig,
    prove_bridge_service_secret_storage,
)
from .powershell import ps_literal, run_powershell_json
from .secure_mcp_tunnel import TunnelRuntimeApiKeyStore
from .secure_mcp_tunnel_package import (
    TunnelRuntimePackageConfig,
    prove_installed_tunnel_runtime,
)


_HEALTH_PARENT = DEFAULT_BRIDGE_RUNTIME_ROOT / "tunnel-health"
_HEALTH_FILE = "health-url.txt"
_RESULT_KEYS = frozenset(
    {
        "ready",
        "service_name",
        "service_sid",
        "service_state",
        "service_process_id",
        "tunnel_process_id",
        "tunnel_parent_process_id",
        "tunnel_executable_path",
        "tunnel_executable_sha256",
        "health_attempt_path",
        "health_url_path",
        "health_base_url",
        "health_listener_host",
        "health_listener_port",
        "readiness_url",
        "readiness_status_code",
        "readiness_body_class",
        "service_stable_after_probe",
        "tunnel_stable_after_probe",
        "health_listener_stable_after_probe",
    }
)


class SecureMcpTunnelNativeQualificationError(RuntimeError):
    pass


def _windows_path(value: Path | str) -> str:
    return str(PureWindowsPath(str(value)))


def _build_native_tunnel_qualification_script(
    *,
    service_sid: str,
    service_process_id: int,
    executable_path: Path,
    executable_sha256: str,
) -> str:
    sid = require_hms_bridge_service_sid(service_sid)
    if isinstance(service_process_id, bool) or not isinstance(service_process_id, int) or service_process_id <= 0:
        raise SecureMcpTunnelNativeQualificationError("service_process_id must be a positive integer")
    if not isinstance(executable_path, Path):
        raise TypeError("executable_path must be pathlib.Path")
    if (
        not isinstance(executable_sha256, str)
        or len(executable_sha256) != 64
        or executable_sha256 != executable_sha256.lower()
        or any(c not in "0123456789abcdef" for c in executable_sha256)
    ):
        raise SecureMcpTunnelNativeQualificationError("executable_sha256 is invalid")

    service_name = ps_literal(HMS_BRIDGE_SERVICE_NAME)
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    expected_sid = ps_literal(sid)
    expected_executable = ps_literal(_windows_path(executable_path))
    expected_sha = ps_literal(executable_sha256)
    health_parent = ps_literal(_windows_path(_HEALTH_PARENT))
    health_file = ps_literal(_HEALTH_FILE)
    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$serviceAccount = {service_account}
$expectedServiceSid = {expected_sid}
$expectedServicePid = [uint32]{service_process_id}
$expectedExecutable = [System.IO.Path]::GetFullPath({expected_executable})
$expectedExecutableSha = {expected_sha}
$healthParent = [System.IO.Path]::GetFullPath({health_parent})
$healthFileName = {health_file}

function Assert-NoReparse([string]$path) {{
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    throw 'Tunnel native qualification authority is a reparse point'
  }}
  return $item
}}
function Get-ExactService {{
  $rows = @(Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
  if ($rows.Count -ne 1) {{ throw 'Expected exactly one HMSBridge service' }}
  $svc = $rows[0]
  if ([string]$svc.StartName -ine $serviceAccount) {{ throw 'HMSBridge service account differs' }}
  if ([string]$svc.StartMode -ne 'Manual') {{ throw 'HMSBridge start mode differs during tunnel qualification' }}
  $sid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
  if ($sid -ne $expectedServiceSid) {{ throw 'HMSBridge service SID differs' }}
  if ([string]$svc.State -ne 'Running' -or [uint32]$svc.ProcessId -ne $expectedServicePid) {{
    throw 'HMSBridge running PID differs from activation authority'
  }}
  return $svc
}}
function Get-ExactTunnelProcess([uint32]$pid) {{
  $rows = @(Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction Stop)
  if ($rows.Count -ne 1) {{ throw 'Expected exactly one tunnel child process' }}
  $proc = $rows[0]
  if ([uint32]$proc.ParentProcessId -ne $expectedServicePid) {{ throw 'Tunnel process parent is not HMSBridge' }}
  if ([string]::IsNullOrWhiteSpace([string]$proc.ExecutablePath)) {{ throw 'Tunnel process executable path is unavailable' }}
  $actualPath = [System.IO.Path]::GetFullPath([string]$proc.ExecutablePath)
  if ($actualPath -ine $expectedExecutable) {{ throw 'Tunnel process executable path differs' }}
  $sha = (Get-FileHash -LiteralPath $actualPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($sha -ne $expectedExecutableSha) {{ throw 'Tunnel process executable SHA-256 differs' }}
  return $proc
}}
function Get-ExactHealthListener([int]$port) {{
  $rows = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop | Where-Object {{
    $_.LocalAddress -eq '127.0.0.1'
  }})
  if ($rows.Count -ne 1) {{ throw 'Expected exactly one tunnel health loopback listener' }}
  return $rows[0]
}}

Get-ExactService | Out-Null
$healthParentItem = Assert-NoReparse $healthParent
if (-not $healthParentItem.PSIsContainer) {{ throw 'Tunnel health parent is not a directory' }}
$attempts = @(Get-ChildItem -LiteralPath $healthParent -Force -Directory -ErrorAction Stop)
if ($attempts.Count -ne 1) {{ throw 'Expected exactly one active tunnel health attempt' }}
$attempt = $attempts[0]
if ($attempt.Name -notmatch '^attempt-[0-9a-f]{{32}}$') {{ throw 'Tunnel health attempt name is noncanonical' }}
Assert-NoReparse $attempt.FullName | Out-Null
$entries = @(Get-ChildItem -LiteralPath $attempt.FullName -Force -ErrorAction Stop)
if ($entries.Count -ne 1 -or $entries[0].Name -ne $healthFileName -or $entries[0].PSIsContainer) {{
  throw 'Tunnel health attempt exact entry set differs'
}}
$urlFile = $entries[0]
Assert-NoReparse $urlFile.FullName | Out-Null
$healthBase = [System.IO.File]::ReadAllText($urlFile.FullName, [System.Text.Encoding]::ASCII)
if ($healthBase -ne $healthBase.Trim()) {{ throw 'Tunnel health URL contains whitespace' }}
$match = [regex]::Match($healthBase, '^http://127\\.0\\.0\\.1:([0-9]{{1,5}})$')
if (-not $match.Success) {{ throw 'Tunnel health URL is noncanonical' }}
$healthPort = [int]$match.Groups[1].Value
if ($healthPort -lt 1 -or $healthPort -gt 65535) {{ throw 'Tunnel health URL port is invalid' }}
$listener = Get-ExactHealthListener $healthPort
$tunnelPid = [uint32]$listener.OwningProcess
if ($tunnelPid -eq 0 -or $tunnelPid -eq $expectedServicePid) {{ throw 'Tunnel health listener PID is invalid' }}
$tunnel = Get-ExactTunnelProcess $tunnelPid

$readyUrl = $healthBase + '/readyz'
$response = Invoke-WebRequest -UseBasicParsing -Uri $readyUrl -Method Get -TimeoutSec 5 -ErrorAction Stop
$status = [int]$response.StatusCode
$body = ([string]$response.Content).Trim()
if ($status -ne 200) {{ throw 'Tunnel /readyz did not return HTTP 200' }}
$bodyClass = $null
if ($body -eq 'ready') {{
  $bodyClass = 'ready'
}} elseif ($body -match '^ready \\(mcp initialize requires auth: .+\\)$') {{
  $bodyClass = 'mcp_auth_required'
}} else {{
  throw 'Tunnel /readyz body is not an HMS-approved ready form'
}}

$serviceAfter = Get-ExactService
$tunnelAfter = Get-ExactTunnelProcess $tunnelPid
$listenerAfter = Get-ExactHealthListener $healthPort
if ([uint32]$listenerAfter.OwningProcess -ne $tunnelPid) {{ throw 'Tunnel health listener PID changed after readiness probe' }}
$healthBaseAfter = [System.IO.File]::ReadAllText($urlFile.FullName, [System.Text.Encoding]::ASCII)
if ($healthBaseAfter -ne $healthBase) {{ throw 'Tunnel health URL authority changed after readiness probe' }}

[pscustomobject]@{{
  ready = $true
  service_name = [string]$serviceAfter.Name
  service_sid = [string]$expectedServiceSid
  service_state = [string]$serviceAfter.State
  service_process_id = [uint32]$serviceAfter.ProcessId
  tunnel_process_id = [uint32]$tunnelPid
  tunnel_parent_process_id = [uint32]$tunnelAfter.ParentProcessId
  tunnel_executable_path = [string]$expectedExecutable
  tunnel_executable_sha256 = [string]$expectedExecutableSha
  health_attempt_path = [string]$attempt.FullName
  health_url_path = [string]$urlFile.FullName
  health_base_url = [string]$healthBase
  health_listener_host = '127.0.0.1'
  health_listener_port = [int]$healthPort
  readiness_url = [string]$readyUrl
  readiness_status_code = [int]$status
  readiness_body_class = [string]$bodyClass
  service_stable_after_probe = $true
  tunnel_stable_after_probe = $true
  health_listener_stable_after_probe = $true
}}
""".strip()


def _validate_native_tunnel_evidence(
    result: dict[str, object],
    *,
    service_sid: str,
    service_process_id: int,
    executable_path: Path,
    executable_sha256: str,
) -> dict[str, object]:
    if frozenset(result) != _RESULT_KEYS:
        raise SecureMcpTunnelNativeQualificationError("native tunnel evidence schema is invalid")
    expected = {
        "ready": True,
        "service_name": HMS_BRIDGE_SERVICE_NAME,
        "service_sid": service_sid,
        "service_state": "Running",
        "service_process_id": service_process_id,
        "tunnel_parent_process_id": service_process_id,
        "tunnel_executable_sha256": executable_sha256,
        "health_listener_host": "127.0.0.1",
        "readiness_status_code": 200,
        "service_stable_after_probe": True,
        "tunnel_stable_after_probe": True,
        "health_listener_stable_after_probe": True,
    }
    for key, wanted in expected.items():
        if result.get(key) != wanted:
            raise SecureMcpTunnelNativeQualificationError(f"native tunnel evidence differs: {key}")
    tunnel_pid = result.get("tunnel_process_id")
    if not isinstance(tunnel_pid, int) or isinstance(tunnel_pid, bool) or tunnel_pid <= 0 or tunnel_pid == service_process_id:
        raise SecureMcpTunnelNativeQualificationError("native tunnel process id is invalid")
    expected_executable = _windows_path(executable_path)
    observed_executable = result.get("tunnel_executable_path")
    if not isinstance(observed_executable, str) or observed_executable.casefold() != expected_executable.casefold():
        raise SecureMcpTunnelNativeQualificationError("native tunnel executable path differs")
    port = result.get("health_listener_port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise SecureMcpTunnelNativeQualificationError("native tunnel health port is invalid")
    base = result.get("health_base_url")
    if not isinstance(base, str):
        raise SecureMcpTunnelNativeQualificationError("native tunnel health URL is invalid")
    parsed = urlsplit(base)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise SecureMcpTunnelNativeQualificationError("native tunnel health URL port is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed_port != port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or base != f"http://127.0.0.1:{port}"
    ):
        raise SecureMcpTunnelNativeQualificationError("native tunnel health URL differs from exact loopback authority")
    readiness_url = result.get("readiness_url")
    if readiness_url != base + "/readyz":
        raise SecureMcpTunnelNativeQualificationError("native tunnel readiness URL differs")
    body_class = result.get("readiness_body_class")
    if body_class not in {"ready", "mcp_auth_required"}:
        raise SecureMcpTunnelNativeQualificationError("native tunnel readiness body class is not approved")
    attempt_path = result.get("health_attempt_path")
    health_url_path = result.get("health_url_path")
    if not isinstance(attempt_path, str) or not isinstance(health_url_path, str):
        raise SecureMcpTunnelNativeQualificationError("native tunnel health paths are invalid")
    attempt = PureWindowsPath(attempt_path)
    expected_parent = PureWindowsPath(_windows_path(_HEALTH_PARENT))
    attempt_token = attempt.name.removeprefix("attempt-") if attempt.name.startswith("attempt-") else ""
    if (
        str(attempt.parent).casefold() != str(expected_parent).casefold()
        or len(attempt_token) != 32
        or attempt_token != attempt_token.lower()
        or any(c not in "0123456789abcdef" for c in attempt_token)
    ):
        raise SecureMcpTunnelNativeQualificationError("native tunnel health attempt path differs")
    if PureWindowsPath(health_url_path) != attempt / _HEALTH_FILE:
        raise SecureMcpTunnelNativeQualificationError("native tunnel health URL-file path differs")
    return dict(result)


def qualify_running_secure_mcp_tunnel(
    *,
    service_sid: str,
    service_process_id: int,
) -> dict[str, object]:
    """Independently qualify the live tunnel child while HMSBridge is Running."""

    sid = require_hms_bridge_service_sid(service_sid)
    if isinstance(service_process_id, bool) or not isinstance(service_process_id, int) or service_process_id <= 0:
        raise SecureMcpTunnelNativeQualificationError("service_process_id must be a positive integer")
    secret_storage = BridgeServiceSecretStorageConfig(
        root=DEFAULT_BRIDGE_RUNTIME_ROOT / "secrets" / "service-runtime",
        bridge_reader_sid=sid,
    )
    secret_storage.validate()
    pre_secret = prove_bridge_service_secret_storage(secret_storage, require_pairing_key=True)
    if pre_secret.get("ready") is not True or pre_secret.get("secret_file_acls_exact") is not True:
        raise SecureMcpTunnelNativeQualificationError("pre-probe service secret authority differs")
    key_store = TunnelRuntimeApiKeyStore(secret_storage)
    pre_key = key_store.load()
    package = prove_installed_tunnel_runtime(TunnelRuntimePackageConfig(), service_sid=sid, prove_acl=True)
    try:
        result = run_powershell_json(
            _build_native_tunnel_qualification_script(
                service_sid=sid,
                service_process_id=service_process_id,
                executable_path=Path(package.executable_path),
                executable_sha256=package.executable_sha256,
            ),
            timeout_seconds=30,
        )
        evidence = _validate_native_tunnel_evidence(
            result,
            service_sid=sid,
            service_process_id=service_process_id,
            executable_path=Path(package.executable_path),
            executable_sha256=package.executable_sha256,
        )
        post_package = prove_installed_tunnel_runtime(TunnelRuntimePackageConfig(), service_sid=sid, prove_acl=True)
        if post_package.executable_sha256 != package.executable_sha256:
            raise SecureMcpTunnelNativeQualificationError("tunnel package authority changed across native probe")
        post_secret = prove_bridge_service_secret_storage(secret_storage, require_pairing_key=True)
        if post_secret.get("ready") is not True or post_secret.get("secret_file_acls_exact") is not True:
            raise SecureMcpTunnelNativeQualificationError("post-probe service secret authority differs")
        post_key = key_store.load()
        try:
            if not secrets.compare_digest(pre_key, post_key):
                raise SecureMcpTunnelNativeQualificationError("tunnel API-key authority changed across native probe")
        finally:
            post_key = ""
        return evidence
    finally:
        pre_key = ""
