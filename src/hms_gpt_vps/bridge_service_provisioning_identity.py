from __future__ import annotations

from collections.abc import Callable
from typing import Any

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
EvidenceRunner = Callable[..., dict[str, Any]]


class HmsBridgeProvisioningIdentityError(PermissionError):
    pass


def build_hms_bridge_provisioning_identity_script() -> str:
    service_name = ps_literal(HMS_BRIDGE_SERVICE_NAME)
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$serviceAccount = {service_account}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {{
  throw 'HMSBridge provisioning process token has no user SID'
}}
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$elevatedAdministrator = $principal.IsInRole(
  [System.Security.Principal.WindowsBuiltInRole]::Administrator
)
$rows = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
if ($rows.Count -ne 1) {{
  throw 'Expected exactly one HMSBridge SCM service during provisioning'
}}
$service = $rows[0]
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


def prove_hms_bridge_provisioning_identity(
    *,
    runner: EvidenceRunner | None = None,
) -> dict[str, object]:
    """Prove an elevated administrator and a quiescent exact HMSBridge SCM target."""

    execute = run_powershell_json if runner is None else runner
    result = execute(
        build_hms_bridge_provisioning_identity_script(),
        timeout_seconds=30,
    )
    if frozenset(result) != _RESULT_KEYS:
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge provisioning identity evidence schema is invalid"
        )
    if result.get("elevated_administrator") is not True:
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge provisioning requires an elevated Administrator process token"
        )
    process_sid = result.get("process_sid")
    if (
        not isinstance(process_sid, str)
        or not process_sid
        or process_sid != process_sid.strip()
        or process_sid.startswith("S-1-5-80-")
    ):
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge provisioning process SID is invalid or is a service SID"
        )
    identity_name = result.get("identity_name")
    if (
        not isinstance(identity_name, str)
        or not identity_name
        or identity_name.casefold() == HMS_BRIDGE_SERVICE_ACCOUNT.casefold()
    ):
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge provisioning must not run as the HMSBridge virtual account"
        )
    if result.get("service_name") != HMS_BRIDGE_SERVICE_NAME:
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge SCM service name differs from authority"
        )
    service_start_name = result.get("service_start_name")
    if (
        not isinstance(service_start_name, str)
        or service_start_name.casefold() != HMS_BRIDGE_SERVICE_ACCOUNT.casefold()
    ):
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge SCM service account differs from virtual-account authority"
        )
    if result.get("service_start_mode") != "Manual":
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge must remain Manual during privileged provisioning"
        )
    if result.get("service_state") != "Stopped":
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge must remain Stopped during privileged provisioning"
        )
    try:
        require_hms_bridge_service_sid(result.get("service_sid"))
    except PermissionError as exc:
        raise HmsBridgeProvisioningIdentityError(
            "HMSBridge service SID evidence is invalid"
        ) from exc
    return dict(result)
