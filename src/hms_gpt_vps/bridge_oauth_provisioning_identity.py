from __future__ import annotations

from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    HMS_BRIDGE_SERVICE_NAME,
    require_hms_bridge_service_sid,
)
from .powershell import ps_literal, run_powershell_json


_RESULT_KEYS = frozenset(
    {
        "elevated_administrator",
        "process_sid",
        "identity_name",
        "service_name",
        "service_start_name",
        "service_start_mode",
        "service_state",
        "service_sid",
    }
)


class BridgeOAuthProvisioningIdentityError(PermissionError):
    pass


def build_bridge_oauth_provisioning_identity_script() -> str:
    service_name = ps_literal(HMS_BRIDGE_SERVICE_NAME)
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$serviceAccount = {service_account}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {{
  throw 'OAuth provisioning process token has no user SID'
}}
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$elevatedAdministrator = $principal.IsInRole(
  [System.Security.Principal.WindowsBuiltInRole]::Administrator
)
$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
if ($null -eq $service) {{
  throw 'HMSBridge SCM service is missing'
}}
$serviceSid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate(
  [System.Security.Principal.SecurityIdentifier]
).Value
[pscustomobject]@{{
  elevated_administrator = [bool]$elevatedAdministrator
  process_sid = [string]$identity.User.Value
  identity_name = [string]$identity.Name
  service_name = [string]$service.Name
  service_start_name = [string]$service.StartName
  service_start_mode = [string]$service.StartMode
  service_state = [string]$service.State
  service_sid = [string]$serviceSid
}}
""".strip()


def prove_bridge_oauth_provisioning_identity() -> dict[str, object]:
    """Prove an elevated admin provisioning process and a quiescent HMSBridge SCM target.

    This proof is deliberately run before stdin is read so an unelevated or
    incorrectly staged invocation cannot cause secret bytes to enter process
    memory. The same proof is repeated immediately before and after publication.
    """

    result = run_powershell_json(
        build_bridge_oauth_provisioning_identity_script(),
        timeout_seconds=30,
    )
    if frozenset(result) != _RESULT_KEYS:
        raise BridgeOAuthProvisioningIdentityError(
            "OAuth provisioning identity evidence schema is invalid"
        )
    if result.get("elevated_administrator") is not True:
        raise BridgeOAuthProvisioningIdentityError(
            "OAuth provisioning requires an elevated Administrator process token"
        )
    process_sid = result.get("process_sid")
    if (
        not isinstance(process_sid, str)
        or not process_sid
        or process_sid != process_sid.strip()
        or process_sid.startswith("S-1-5-80-")
    ):
        raise BridgeOAuthProvisioningIdentityError(
            "OAuth provisioning process SID is invalid or is a service SID"
        )
    identity_name = result.get("identity_name")
    if (
        not isinstance(identity_name, str)
        or not identity_name
        or identity_name.casefold() == HMS_BRIDGE_SERVICE_ACCOUNT.casefold()
    ):
        raise BridgeOAuthProvisioningIdentityError(
            "OAuth provisioning must not run as HMSBridge"
        )
    if result.get("service_name") != HMS_BRIDGE_SERVICE_NAME:
        raise BridgeOAuthProvisioningIdentityError(
            "OAuth provisioning SCM service name differs from authority"
        )
    service_start_name = result.get("service_start_name")
    if (
        not isinstance(service_start_name, str)
        or service_start_name.casefold() != HMS_BRIDGE_SERVICE_ACCOUNT.casefold()
    ):
        raise BridgeOAuthProvisioningIdentityError(
            "HMSBridge SCM service account differs from virtual-account authority"
        )
    if result.get("service_start_mode") != "Manual":
        raise BridgeOAuthProvisioningIdentityError(
            "HMSBridge must remain Manual while OAuth credential is provisioned"
        )
    if result.get("service_state") != "Stopped":
        raise BridgeOAuthProvisioningIdentityError(
            "HMSBridge must be Stopped while OAuth credential is provisioned"
        )
    require_hms_bridge_service_sid(result.get("service_sid"))
    return dict(result)
