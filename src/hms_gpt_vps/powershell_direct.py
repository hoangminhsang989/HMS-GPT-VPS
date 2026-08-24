from __future__ import annotations

from dataclasses import dataclass, field
import base64
import uuid

from .powershell import ps_literal, run_powershell_json


_MAX_GUEST_SCRIPT_BYTES = 16 * 1024
_MAX_SECRET_PAYLOAD_BYTES = 8 * 1024


@dataclass(frozen=True)
class PowerShellDirectCredential:
    username: str
    password: str = field(repr=False)

    def validate(self) -> None:
        if not self.username.strip():
            raise ValueError("PowerShell Direct username is required")
        if not self.password:
            raise ValueError("PowerShell Direct password is required")


def _normalize_vm_id(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("VMId is required")
    try:
        return str(uuid.UUID(value.strip())).lower()
    except (ValueError, AttributeError) as exc:
        raise ValueError("VMId must be a valid GUID") from exc


def build_powershell_direct_host_script(
    vm_name: str,
    *,
    vm_id: str | None = None,
) -> str:
    """Build the host wrapper without embedding credentials, guest script or payload.

    Credentials, the base64-encoded guest script and an optional short-lived
    secret payload are supplied only through the child PowerShell process
    environment. The child removes all four environment variables before the
    guest invocation. The optional payload then exists only in process memory
    and is passed as the single `-ArgumentList` value to a guest script that
    explicitly declares a parameter.

    Early bootstrap callers may address a VM by name before a stable VMId has
    been persisted. Once a managed VMId exists, callers must pass ``vm_id`` so
    the same PowerShell process resolves the exact GUID, verifies its expected
    name, and invokes PowerShell Direct with ``-VMId`` rather than re-resolving
    a mutable VM name at the guest-execution boundary.
    """
    if not vm_name.strip():
        raise ValueError("VM name is required")
    vm = ps_literal(vm_name)
    if vm_id is None:
        target_setup = ""
        invoke_target = "-VMName $vmName"
    else:
        normalized_vm_id = _normalize_vm_id(vm_id)
        target_setup = rf"""
$vmId = [guid]{ps_literal(normalized_vm_id)}
$managedVm = Get-VM -Id $vmId -ErrorAction Stop
if ($managedVm.Name -ine $vmName) {{
  throw 'PowerShell Direct VMId resolves to a different VM name'
}}
""".strip()
        invoke_target = "-VMId $vmId"

    return rf"""
$ErrorActionPreference = 'Stop'
$vmName = {vm}
{target_setup}
$username = $env:HMS_PSDIRECT_USERNAME
$passwordText = $env:HMS_PSDIRECT_PASSWORD
$guestScriptB64 = $env:HMS_PSDIRECT_SCRIPT_B64
$payloadB64 = $env:HMS_PSDIRECT_PAYLOAD_B64
if ([string]::IsNullOrWhiteSpace($username)) {{ throw 'PowerShell Direct username missing' }}
if ([string]::IsNullOrEmpty($passwordText)) {{ throw 'PowerShell Direct password missing' }}
if ([string]::IsNullOrWhiteSpace($guestScriptB64)) {{ throw 'PowerShell Direct guest script missing' }}
$hasPayload = -not [string]::IsNullOrWhiteSpace($payloadB64)

$securePassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
$credential = [System.Management.Automation.PSCredential]::new($username, $securePassword)
$guestScriptText = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String($guestScriptB64)
)
$guestScript = [scriptblock]::Create($guestScriptText)

Remove-Item Env:\HMS_PSDIRECT_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:\HMS_PSDIRECT_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:\HMS_PSDIRECT_SCRIPT_B64 -ErrorAction SilentlyContinue
Remove-Item Env:\HMS_PSDIRECT_PAYLOAD_B64 -ErrorAction SilentlyContinue
$passwordText = $null
$guestScriptB64 = $null

if ($hasPayload) {{
  Invoke-Command {invoke_target} -Credential $credential -ScriptBlock $guestScript -ArgumentList $payloadB64 -ErrorAction Stop
}} else {{
  Invoke-Command {invoke_target} -Credential $credential -ScriptBlock $guestScript -ErrorAction Stop
}}
$payloadB64 = $null
""".strip()


def _direct_environment(
    credential: PowerShellDirectCredential,
    guest_script: str,
    *,
    secret_payload: bytes | None = None,
) -> dict[str, str]:
    credential.validate()
    if not guest_script.strip():
        raise ValueError("guest PowerShell script is required")
    encoded = guest_script.encode("utf-8")
    if len(encoded) > _MAX_GUEST_SCRIPT_BYTES:
        raise ValueError(
            f"guest PowerShell script exceeds {_MAX_GUEST_SCRIPT_BYTES} byte bootstrap limit"
        )
    environment = {
        "HMS_PSDIRECT_USERNAME": credential.username,
        "HMS_PSDIRECT_PASSWORD": credential.password,
        "HMS_PSDIRECT_SCRIPT_B64": base64.b64encode(encoded).decode("ascii"),
    }
    if secret_payload is not None:
        if not isinstance(secret_payload, bytes):
            raise TypeError("PowerShell Direct secret payload must be bytes")
        if not secret_payload:
            raise ValueError("PowerShell Direct secret payload must not be empty")
        if len(secret_payload) > _MAX_SECRET_PAYLOAD_BYTES:
            raise ValueError(
                f"PowerShell Direct secret payload exceeds {_MAX_SECRET_PAYLOAD_BYTES} byte limit"
            )
        environment["HMS_PSDIRECT_PAYLOAD_B64"] = base64.b64encode(secret_payload).decode(
            "ascii"
        )
    return environment


def run_vm_powershell_json(
    vm_name: str,
    credential: PowerShellDirectCredential,
    guest_script: str,
    *,
    timeout_seconds: int = 120,
    secret_payload: bytes | None = None,
    vm_id: str | None = None,
) -> dict[str, object]:
    """Run a bootstrap-scoped PowerShell script inside a Hyper-V guest.

    The bootstrap credential, guest script and optional short-lived secret
    payload are absent from the command line and host script text. Callers must
    not log the child environment or payload. Guest scripts using a payload must
    declare one string parameter and base64-decode it inside the guest.

    Managed late-guest callers must provide ``vm_id`` so invocation is bound to
    the persisted Hyper-V GUID in the same host process that establishes the
    PowerShell Direct session.
    """
    return run_powershell_json(
        build_powershell_direct_host_script(vm_name, vm_id=vm_id),
        timeout_seconds=timeout_seconds,
        env=_direct_environment(
            credential,
            guest_script,
            secret_payload=secret_payload,
        ),
    )


def run_vm_powershell_json_by_id(
    vm_id: str,
    vm_name: str,
    credential: PowerShellDirectCredential,
    guest_script: str,
    *,
    timeout_seconds: int = 120,
    secret_payload: bytes | None = None,
) -> dict[str, object]:
    """Require a stable Hyper-V VMId for one PowerShell Direct guest call."""
    normalized_vm_id = _normalize_vm_id(vm_id)
    return run_vm_powershell_json(
        vm_name,
        credential,
        guest_script,
        timeout_seconds=timeout_seconds,
        secret_payload=secret_payload,
        vm_id=normalized_vm_id,
    )


def build_readiness_script() -> str:
    """Read-only guest proof required before any bootstrap mutation."""
    return r"""
$profileExists = Test-Path $env:USERPROFILE
[pscustomobject]@{
  computer_name = $env:COMPUTERNAME
  username = $env:USERNAME
  user_profile = $env:USERPROFILE
  profile_exists = [bool]$profileExists
  powershell_version = $PSVersionTable.PSVersion.ToString()
}
""".strip()


def probe_powershell_direct(
    vm_name: str,
    credential: PowerShellDirectCredential,
    *,
    timeout_seconds: int = 60,
) -> dict[str, object]:
    return run_vm_powershell_json(
        vm_name,
        credential,
        build_readiness_script(),
        timeout_seconds=timeout_seconds,
    )
