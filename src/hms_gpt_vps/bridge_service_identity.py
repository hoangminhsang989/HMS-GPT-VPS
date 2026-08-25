from __future__ import annotations

import re

from .powershell import ps_literal, run_powershell_json


HMS_BRIDGE_SERVICE_NAME = "HMSBridge"
HMS_BRIDGE_SERVICE_ACCOUNT = r"NT SERVICE\HMSBridge"
BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"
HYPER_V_ADMINISTRATORS_SID = "S-1-5-32-578"
_SERVICE_SID_RE = re.compile(r"^S-1-5-80-(?:\d+-){4}\d+$")
_RESULT_KEYS = frozenset(
    {
        "process_sid",
        "identity_name",
        "dedicated_service_sid",
        "administrators_sid_present",
        "hyperv_administrators_sid_present",
    }
)


class HmsBridgeServiceIdentityError(PermissionError):
    pass


def require_hms_bridge_service_sid(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not _SERVICE_SID_RE.fullmatch(value)
    ):
        raise HmsBridgeServiceIdentityError(
            "HMSBridge service SID must be a canonical NT SERVICE SID"
        )
    return value


def build_hms_bridge_process_identity_script() -> str:
    administrators_sid = ps_literal(BUILTIN_ADMINISTRATORS_SID)
    hyperv_sid = ps_literal(HYPER_V_ADMINISTRATORS_SID)
    return f"""
$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {{
  throw 'HMSBridge process token has no user SID'
}}
$groups = @()
if ($null -ne $identity.Groups) {{
  $groups = @($identity.Groups | ForEach-Object {{ [string]$_.Value }})
}}
$processSid = [string]$identity.User.Value
[pscustomobject]@{{
  process_sid = $processSid
  identity_name = [string]$identity.Name
  dedicated_service_sid = [bool]$processSid.StartsWith('S-1-5-80-')
  administrators_sid_present = [bool]($groups -contains {administrators_sid})
  hyperv_administrators_sid_present = [bool]($groups -contains {hyperv_sid})
}}
""".strip()


def prove_hms_bridge_runtime_identity(expected_service_sid: str) -> dict[str, object]:
    """Prove the long-lived Bridge token is the exact low-privilege virtual account.

    The proof is deliberately based on effective process-token SIDs, not local
    group configuration text. A Bridge service that has been added directly or
    indirectly to Administrators or Hyper-V Administrators therefore fails
    before production secrets or TLS material are accessed.
    """

    expected_sid = require_hms_bridge_service_sid(expected_service_sid)
    result = run_powershell_json(
        build_hms_bridge_process_identity_script(),
        timeout_seconds=30,
    )
    if frozenset(result) != _RESULT_KEYS:
        raise HmsBridgeServiceIdentityError(
            "HMSBridge process identity evidence schema is invalid"
        )
    if result.get("process_sid") != expected_sid:
        raise HmsBridgeServiceIdentityError(
            "HMSBridge process user SID differs from service authority"
        )
    if result.get("dedicated_service_sid") is not True:
        raise HmsBridgeServiceIdentityError(
            "HMSBridge process is not a dedicated NT SERVICE virtual account"
        )
    identity_name = result.get("identity_name")
    if (
        not isinstance(identity_name, str)
        or identity_name.casefold() != HMS_BRIDGE_SERVICE_ACCOUNT.casefold()
    ):
        raise HmsBridgeServiceIdentityError(
            "HMSBridge process identity name differs from virtual-account authority"
        )
    if result.get("administrators_sid_present") is not False:
        raise HmsBridgeServiceIdentityError(
            "HMSBridge process token contains Builtin Administrators"
        )
    if result.get("hyperv_administrators_sid_present") is not False:
        raise HmsBridgeServiceIdentityError(
            "HMSBridge process token contains Hyper-V Administrators"
        )
    return dict(result)
