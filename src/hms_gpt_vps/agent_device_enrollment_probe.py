from __future__ import annotations

import hashlib
from pathlib import PureWindowsPath

from .agent_device_credential_store import (
    AGENT_DEVICE_CREDENTIAL_SCHEMA_VERSION,
    GUEST_DEVICE_CREDENTIAL_FILENAME,
    GUEST_PROTECTION_SCOPE,
    MAX_PROTECTED_DEVICE_CREDENTIAL_BYTES,
)
from .agent_device_enrollment import AgentDeviceEnrollmentConfig
from .agent_transport_protocol import AGENT_DEVICE_SECRET_BYTES, AgentDeviceCredential
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


class AgentDeviceEnrollmentProbeError(RuntimeError):
    pass


def build_agent_device_enrollment_probe_script(
    config: AgentDeviceEnrollmentConfig,
    expected_credential: AgentDeviceCredential,
) -> str:
    """Build a read-only proof of the exact LocalMachine-DPAPI guest credential.

    The device secret itself is never embedded or returned. The host supplies
    only the SHA-256 of the authoritative random Bridge secret, and the guest
    compares that digest after LocalMachine-DPAPI decryption.
    """

    config.validate()
    expected_credential.validate()
    if expected_credential.instance_id != config.instance_id:
        raise ValueError("expected Agent credential belongs to another instance")

    expected_instance = ps_literal(expected_credential.instance_id)
    expected_device = ps_literal(expected_credential.device_id)
    expected_secret_sha = ps_literal(hashlib.sha256(expected_credential.secret).hexdigest())
    state_path = ps_literal(config.guest_state_path)
    filename = ps_literal(GUEST_DEVICE_CREDENTIAL_FILENAME)
    expected_scope = ps_literal(GUEST_PROTECTION_SCOPE)

    return f"""
$ErrorActionPreference = 'Stop'
$statePath = {state_path}
$credentialPath = Join-Path $statePath {filename}
$expectedInstance = {expected_instance}
$expectedDevice = {expected_device}
$expectedSecretSha256 = {expected_secret_sha}
$expectedScope = {expected_scope}
$expectedSchema = {AGENT_DEVICE_CREDENTIAL_SCHEMA_VERSION}
$requiredSecretBytes = {AGENT_DEVICE_SECRET_BYTES}
$maxEnvelopeBytes = {MAX_PROTECTED_DEVICE_CREDENTIAL_BYTES}
$magic = [byte[]]([System.Text.Encoding]::ASCII.GetBytes('HMS-ADC-V1') + [byte[]](0))

if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {{
  [pscustomobject]@{{
    enrollment_ready = $false
    credential_exists = $false
    instance_id = $null
    device_id = $null
    protection_scope = $null
    credential_path = $credentialPath
  }}
  return
}}

$item = Get-Item -LiteralPath $credentialPath -Force -ErrorAction Stop
if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'Agent device credential must not be a reparse point'
}}
if ([int64]$item.Length -le $magic.Length -or [int64]$item.Length -gt $maxEnvelopeBytes) {{
  throw 'Agent device credential envelope size is invalid'
}}

$raw = [System.IO.File]::ReadAllBytes($credentialPath)
for ($i = 0; $i -lt $magic.Length; $i++) {{
  if ($raw[$i] -ne $magic[$i]) {{
    throw 'Agent device credential format marker mismatch'
  }}
}}
$cipher = New-Object byte[] ($raw.Length - $magic.Length)
[System.Array]::Copy($raw, $magic.Length, $cipher, 0, $cipher.Length)
$plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
  $cipher,
  $null,
  [System.Security.Cryptography.DataProtectionScope]::LocalMachine
)
try {{
  $payload = [System.Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json -ErrorAction Stop
}} finally {{
  $plain = $null
  $cipher = $null
  $raw = $null
}}

$fields = @($payload.PSObject.Properties.Name | Sort-Object)
if (($fields -join ',') -ne 'device_id,instance_id,protection_scope,schema_version,secret_b64') {{
  throw 'Agent device credential fields do not match schema'
}}
$schemaValue = $payload.schema_version
if (($schemaValue -is [bool]) -or (-not (($schemaValue -is [int]) -or ($schemaValue -is [long])))) {{
  throw 'Agent device credential schema_version must be an integer'
}}
if ([long]$schemaValue -ne $expectedSchema) {{
  throw 'Agent device credential schema mismatch'
}}
if ($payload.instance_id -isnot [string] -or $payload.device_id -isnot [string] -or $payload.protection_scope -isnot [string] -or $payload.secret_b64 -isnot [string]) {{
  throw 'Agent device credential scalar field types are invalid'
}}
$instanceId = $payload.instance_id
$deviceId = $payload.device_id
$scope = $payload.protection_scope
if ($instanceId -cne $expectedInstance) {{
  throw 'Agent device credential instance does not match Bridge authority'
}}
if ($deviceId -cne $expectedDevice) {{
  throw 'Agent device credential device id does not match Bridge authority'
}}
if ($scope -cne $expectedScope) {{
  throw 'Agent device credential protection scope is not LocalMachine'
}}
try {{
  $secret = [Convert]::FromBase64String($payload.secret_b64)
}} catch {{
  throw 'Agent device credential secret is not valid base64'
}}
if ($secret.Length -ne $requiredSecretBytes) {{
  $secret = $null
  throw 'Agent device credential secret length is invalid'
}}
$sha = [System.Security.Cryptography.SHA256]::Create()
try {{
  $digestBytes = $sha.ComputeHash($secret)
  $actualSecretSha256 = ([System.BitConverter]::ToString($digestBytes)).Replace('-', '').ToLowerInvariant()
}} finally {{
  $sha.Dispose()
  $digestBytes = $null
  $secret = $null
}}
if ($actualSecretSha256 -cne $expectedSecretSha256) {{
  $actualSecretSha256 = $null
  throw 'Agent device credential secret does not match Bridge authority'
}}
$actualSecretSha256 = $null
$payload.secret_b64 = $null

[pscustomobject]@{{
  enrollment_ready = $true
  credential_exists = $true
  instance_id = $instanceId
  device_id = $deviceId
  protection_scope = $scope
  credential_path = $credentialPath
}}
""".strip()


def validate_agent_device_enrollment_probe_result(
    result: dict[str, object],
    config: AgentDeviceEnrollmentConfig,
    expected_credential: AgentDeviceCredential,
) -> dict[str, object]:
    """Validate one probe result without truthy/string coercion."""

    config.validate()
    expected_credential.validate()
    if expected_credential.instance_id != config.instance_id:
        raise ValueError("expected Agent credential belongs to another instance")

    required_keys = {
        "enrollment_ready",
        "credential_exists",
        "instance_id",
        "device_id",
        "protection_scope",
        "credential_path",
    }
    if set(result) != required_keys:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment result fields do not match schema"
        )
    if result.get("enrollment_ready") is not True:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent device enrollment is not ready"
        )
    if result.get("credential_exists") is not True:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent credential existence was not proven"
        )
    if result.get("instance_id") != expected_credential.instance_id:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment returned wrong instance_id"
        )
    if result.get("device_id") != expected_credential.device_id:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment returned wrong device_id"
        )
    if result.get("protection_scope") != GUEST_PROTECTION_SCOPE:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment is not LocalMachine-DPAPI protected"
        )
    credential_path = result.get("credential_path")
    if not isinstance(credential_path, str) or not credential_path.strip():
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment returned invalid credential path"
        )
    expected_path = PureWindowsPath(config.guest_state_path) / GUEST_DEVICE_CREDENTIAL_FILENAME
    if PureWindowsPath(credential_path) != expected_path:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment returned unexpected credential path"
        )
    return result


def probe_agent_device_enrollment(
    vm_name: str,
    bootstrap_credential: PowerShellDirectCredential,
    config: AgentDeviceEnrollmentConfig,
    expected_credential: AgentDeviceCredential,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    """Prove the guest DPAPI credential matches the Bridge authority exactly."""

    bootstrap_credential.validate()
    result = run_vm_powershell_json(
        vm_name,
        bootstrap_credential,
        build_agent_device_enrollment_probe_script(config, expected_credential),
        timeout_seconds=timeout_seconds,
    )
    return validate_agent_device_enrollment_probe_result(
        result,
        config,
        expected_credential,
    )
