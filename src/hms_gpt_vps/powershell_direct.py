from __future__ import annotations

from dataclasses import dataclass, field
import base64

from .powershell import ps_literal, run_powershell_json


_MAX_GUEST_SCRIPT_BYTES = 16 * 1024


@dataclass(frozen=True)
class PowerShellDirectCredential:
    username: str
    password: str = field(repr=False)

    def validate(self) -> None:
        if not self.username.strip():
            raise ValueError("PowerShell Direct username is required")
        if not self.password:
            raise ValueError("PowerShell Direct password is required")


def build_powershell_direct_host_script(vm_name: str) -> str:
    """Build the host wrapper without embedding username/password/guest script.

    Credentials and the base64-encoded guest script are supplied only through
    the child PowerShell process environment. The child removes those variables
    immediately after creating the PSCredential/ScriptBlock.
    """
    if not vm_name.strip():
        raise ValueError("VM name is required")
    vm = ps_literal(vm_name)
    return f"""
$ErrorActionPreference = 'Stop'
$vmName = {vm}
$username = $env:HMS_PSDIRECT_USERNAME
$passwordText = $env:HMS_PSDIRECT_PASSWORD
$guestScriptB64 = $env:HMS_PSDIRECT_SCRIPT_B64
if ([string]::IsNullOrWhiteSpace($username)) {{ throw 'PowerShell Direct username missing' }}
if ([string]::IsNullOrEmpty($passwordText)) {{ throw 'PowerShell Direct password missing' }}
if ([string]::IsNullOrWhiteSpace($guestScriptB64)) {{ throw 'PowerShell Direct guest script missing' }}

$securePassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
$credential = [System.Management.Automation.PSCredential]::new($username, $securePassword)
$guestScriptText = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String($guestScriptB64)
)
$guestScript = [scriptblock]::Create($guestScriptText)

Remove-Item Env:\HMS_PSDIRECT_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:\HMS_PSDIRECT_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:\HMS_PSDIRECT_SCRIPT_B64 -ErrorAction SilentlyContinue
$passwordText = $null
$guestScriptB64 = $null

Invoke-Command -VMName $vmName -Credential $credential -ScriptBlock $guestScript -ErrorAction Stop
""".strip()


def _direct_environment(
    credential: PowerShellDirectCredential,
    guest_script: str,
) -> dict[str, str]:
    credential.validate()
    if not guest_script.strip():
        raise ValueError("guest PowerShell script is required")
    encoded = guest_script.encode("utf-8")
    if len(encoded) > _MAX_GUEST_SCRIPT_BYTES:
        raise ValueError(
            f"guest PowerShell script exceeds {_MAX_GUEST_SCRIPT_BYTES} byte bootstrap limit"
        )
    return {
        "HMS_PSDIRECT_USERNAME": credential.username,
        "HMS_PSDIRECT_PASSWORD": credential.password,
        "HMS_PSDIRECT_SCRIPT_B64": base64.b64encode(encoded).decode("ascii"),
    }


def run_vm_powershell_json(
    vm_name: str,
    credential: PowerShellDirectCredential,
    guest_script: str,
    *,
    timeout_seconds: int = 120,
) -> dict[str, object]:
    """Run a bootstrap-scoped PowerShell script inside a Hyper-V guest.

    The secret is absent from the command line and host script text. Callers
    must not log the child environment or the returned guest script payload.
    """
    return run_powershell_json(
        build_powershell_direct_host_script(vm_name),
        timeout_seconds=timeout_seconds,
        env=_direct_environment(credential, guest_script),
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
