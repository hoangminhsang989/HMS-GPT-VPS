from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import PureWindowsPath

from .agent_device_credential_store import (
    AgentDeviceCredentialConflictError,
    AgentDeviceCredentialIntegrityError,
    BridgeAgentDeviceCredentialStore,
    GUEST_DEVICE_CREDENTIAL_FILENAME,
)
from .agent_transport_protocol import AGENT_DEVICE_SECRET_BYTES, AgentDeviceCredential
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


AGENT_DEVICE_ENROLLMENT_SCHEMA_VERSION = 1
DEFAULT_GUEST_STATE_PATH = r"C:\ProgramData\HMS-GPT-VPS\State"
_MAX_ENROLLMENT_PAYLOAD_BYTES = 4096
_SAFE_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


class AgentDeviceEnrollmentError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentDeviceEnrollmentConfig:
    instance_id: str
    guest_state_path: str = DEFAULT_GUEST_STATE_PATH

    def validate(self) -> None:
        _validate_identifier(self.instance_id, "instance_id")
        if not isinstance(self.guest_state_path, str) or not self.guest_state_path.strip():
            raise ValueError("guest_state_path is required")
        path = PureWindowsPath(self.guest_state_path)
        if not path.is_absolute():
            raise ValueError("guest_state_path must be an absolute Windows path")
        if any(part in {".", ".."} for part in path.parts):
            raise ValueError("guest_state_path must not contain relative traversal")


@dataclass(frozen=True)
class AgentDeviceEnrollmentResult:
    instance_id: str
    device_id: str
    credential_path: str

    def validate(self) -> None:
        _validate_identifier(self.instance_id, "instance_id")
        _validate_identifier(self.device_id, "device_id")
        if not self.credential_path.strip():
            raise ValueError("credential_path is required")


def _validate_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError(f"{name} is invalid")
    if any(char not in _SAFE_IDENTIFIER_CHARS for char in value):
        raise ValueError(f"{name} contains unsupported characters")


def load_or_create_bridge_credential(
    store: BridgeAgentDeviceCredentialStore,
    instance_id: str,
) -> AgentDeviceCredential:
    """Return one stable Bridge-side credential for a managed instance.

    The Bridge copy is authoritative. A provisioning retry never rotates an
    existing identity. Concurrent first-time creators may generate different
    candidates, but all losing creators load and return the single credential
    that won the create-only publication race.
    """
    _validate_identifier(instance_id, "instance_id")
    try:
        return store.load(expected_instance_id=instance_id)
    except FileNotFoundError:
        pass

    candidate = AgentDeviceCredential.generate(instance_id)
    try:
        return store.save_create_only(candidate)
    except (AgentDeviceCredentialConflictError, AgentDeviceCredentialIntegrityError):
        # A concurrent publisher can win with a different generated device_id.
        # Reload only by instance_id. Corruption/wrong-instance still fails
        # closed because load() will raise the integrity error again.
        return store.load(expected_instance_id=instance_id)


def _build_enrollment_payload(credential: AgentDeviceCredential) -> bytes:
    credential.validate()
    payload = {
        "schema_version": AGENT_DEVICE_ENROLLMENT_SCHEMA_VERSION,
        "instance_id": credential.instance_id,
        "device_id": credential.device_id,
        "secret_b64": base64.b64encode(credential.secret).decode("ascii"),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > _MAX_ENROLLMENT_PAYLOAD_BYTES:
        raise AgentDeviceEnrollmentError("Agent device enrollment payload exceeds limit")
    return encoded


def build_guest_device_enrollment_script(config: AgentDeviceEnrollmentConfig) -> str:
    """Build the secret-free guest script used before HMSAgent service start.

    The credential arrives only through the PowerShell Direct secret payload.
    The script creates the State directory with a pre-service SYSTEM/Admin ACL
    when absent, protects the credential with LocalMachine DPAPI, and publishes
    the file create-only. Existing files must decrypt to the exact same
    credential; they are never overwritten or silently rotated.
    """
    config.validate()
    expected_instance = ps_literal(config.instance_id)
    state_path = ps_literal(config.guest_state_path)
    filename = ps_literal(GUEST_DEVICE_CREDENTIAL_FILENAME)
    secret_bytes = AGENT_DEVICE_SECRET_BYTES
    schema_version = AGENT_DEVICE_ENROLLMENT_SCHEMA_VERSION

    return f"""
param([Parameter(Mandatory=$true)][string]$PayloadB64)
$ErrorActionPreference = 'Stop'
$expectedInstance = {expected_instance}
$statePath = {state_path}
$credentialFileName = {filename}
$credentialPath = Join-Path $statePath $credentialFileName
$schemaVersion = {schema_version}
$requiredSecretBytes = {secret_bytes}
$magic = [byte[]]([System.Text.Encoding]::ASCII.GetBytes('HMS-ADC-V1') + [byte[]](0))

function Test-HmsIdentifier([string]$Value) {{
  return (-not [string]::IsNullOrWhiteSpace($Value)) -and
    $Value.Length -le 128 -and
    $Value -match '^[A-Za-z0-9_-]+$'
}}

function Read-HmsStoredCredential {{
  if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {{
    return $null
  }}
  $raw = [System.IO.File]::ReadAllBytes($credentialPath)
  if ($raw.Length -le $magic.Length) {{ throw 'Agent device credential file is incomplete' }}
  for ($i = 0; $i -lt $magic.Length; $i++) {{
    if ($raw[$i] -ne $magic[$i]) {{ throw 'Agent device credential format marker mismatch' }}
  }}
  $cipher = New-Object byte[] ($raw.Length - $magic.Length)
  [System.Array]::Copy($raw, $magic.Length, $cipher, 0, $cipher.Length)
  $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $cipher,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
  )
  try {{
    $stored = [System.Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json -ErrorAction Stop
  }} finally {{
    $plain = $null
    $cipher = $null
    $raw = $null
  }}
  if ([int]$stored.schema_version -ne $schemaVersion) {{ throw 'Agent device credential schema mismatch' }}
  if ([string]$stored.protection_scope -ne 'local-machine') {{ throw 'Agent device credential scope mismatch' }}
  if (-not (Test-HmsIdentifier ([string]$stored.instance_id))) {{ throw 'Stored instance_id is invalid' }}
  if (-not (Test-HmsIdentifier ([string]$stored.device_id))) {{ throw 'Stored device_id is invalid' }}
  return $stored
}}

function Assert-HmsCredentialMatch($Stored, [string]$InstanceId, [string]$DeviceId, [string]$SecretB64) {{
  if ($null -eq $Stored) {{ throw 'Agent device credential is missing after publication' }}
  if ([string]$Stored.instance_id -ne $InstanceId) {{ throw 'Existing Agent device credential instance conflict' }}
  if ([string]$Stored.device_id -ne $DeviceId) {{ throw 'Existing Agent device credential device conflict' }}
  if ([string]$Stored.secret_b64 -ne $SecretB64) {{ throw 'Existing Agent device credential secret conflict' }}
}}

try {{
  $payloadBytes = [System.Convert]::FromBase64String($PayloadB64)
  $payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json -ErrorAction Stop
}} finally {{
  $PayloadB64 = $null
  $payloadBytes = $null
}}

if ([int]$payload.schema_version -ne $schemaVersion) {{ throw 'Agent enrollment payload schema mismatch' }}
$instanceId = [string]$payload.instance_id
$deviceId = [string]$payload.device_id
$secretB64 = [string]$payload.secret_b64
if (-not (Test-HmsIdentifier $instanceId)) {{ throw 'Enrollment instance_id is invalid' }}
if (-not (Test-HmsIdentifier $deviceId)) {{ throw 'Enrollment device_id is invalid' }}
if ($instanceId -ne $expectedInstance) {{ throw 'Enrollment instance_id does not match managed instance' }}
try {{
  $secret = [System.Convert]::FromBase64String($secretB64)
}} catch {{
  throw 'Enrollment device secret is not valid base64'
}}
if ($secret.Length -ne $requiredSecretBytes) {{ throw 'Enrollment device secret length is invalid' }}

if (-not (Test-Path -LiteralPath $statePath)) {{
  New-Item -ItemType Directory -Path $statePath -Force | Out-Null
  & icacls.exe $statePath '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'Failed to protect Agent State directory ACL' }}
}}
if (-not (Test-Path -LiteralPath $statePath -PathType Container)) {{
  throw 'Agent State path is not a directory'
}}

$existing = Read-HmsStoredCredential
if ($null -ne $existing) {{
  Assert-HmsCredentialMatch $existing $instanceId $deviceId $secretB64
  $secret = $null
  $secretB64 = $null
  [pscustomobject]@{{
    ready = $true
    created = $false
    instance_id = $instanceId
    device_id = $deviceId
    credential_path = $credentialPath
  }}
  return
}}

$storedPayload = [ordered]@{{
  schema_version = $schemaVersion
  protection_scope = 'local-machine'
  instance_id = $instanceId
  device_id = $deviceId
  secret_b64 = $secretB64
}}
$plainBytes = [System.Text.Encoding]::UTF8.GetBytes(($storedPayload | ConvertTo-Json -Compress))
$protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
  $plainBytes,
  $null,
  [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)
$envelope = New-Object byte[] ($magic.Length + $protectedBytes.Length)
[System.Array]::Copy($magic, 0, $envelope, 0, $magic.Length)
[System.Array]::Copy($protectedBytes, 0, $envelope, $magic.Length, $protectedBytes.Length)
$tempPath = Join-Path $statePath (([System.IO.Path]::GetRandomFileName()) + '.tmp')
try {{
  [System.IO.File]::WriteAllBytes($tempPath, $envelope)
  try {{
    [System.IO.File]::Move($tempPath, $credentialPath)
  }} catch [System.IO.IOException] {{
    if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {{ throw }}
  }}
  $verified = Read-HmsStoredCredential
  Assert-HmsCredentialMatch $verified $instanceId $deviceId $secretB64
}} finally {{
  Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
  $secret = $null
  $secretB64 = $null
  $plainBytes = $null
  $protectedBytes = $null
  $envelope = $null
}}

[pscustomobject]@{{
  ready = $true
  created = $true
  instance_id = $instanceId
  device_id = $deviceId
  credential_path = $credentialPath
}}
""".strip()


def enroll_agent_device(
    vm_name: str,
    bootstrap_credential: PowerShellDirectCredential,
    bridge_store: BridgeAgentDeviceCredentialStore,
    config: AgentDeviceEnrollmentConfig,
    *,
    timeout_seconds: int = 120,
) -> AgentDeviceEnrollmentResult:
    """Enroll one stable Agent transport identity into the Windows guest."""
    config.validate()
    credential = load_or_create_bridge_credential(bridge_store, config.instance_id)
    payload = _build_enrollment_payload(credential)
    guest_result = run_vm_powershell_json(
        vm_name,
        bootstrap_credential,
        build_guest_device_enrollment_script(config),
        timeout_seconds=timeout_seconds,
        secret_payload=payload,
    )
    if not bool(guest_result.get("ready", False)):
        raise AgentDeviceEnrollmentError("guest Agent device enrollment postcondition failed")
    if guest_result.get("instance_id") != credential.instance_id:
        raise AgentDeviceEnrollmentError("guest Agent enrollment returned wrong instance_id")
    if guest_result.get("device_id") != credential.device_id:
        raise AgentDeviceEnrollmentError("guest Agent enrollment returned wrong device_id")
    credential_path = guest_result.get("credential_path")
    if not isinstance(credential_path, str) or not credential_path.strip():
        raise AgentDeviceEnrollmentError("guest Agent enrollment returned invalid credential path")
    result = AgentDeviceEnrollmentResult(
        instance_id=credential.instance_id,
        device_id=credential.device_id,
        credential_path=credential_path,
    )
    result.validate()
    return result
