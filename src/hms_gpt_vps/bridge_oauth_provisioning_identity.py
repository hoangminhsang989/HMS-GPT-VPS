from __future__ import annotations

from .bridge_service_provisioning_identity import (
    HmsBridgeProvisioningIdentityError,
    build_hms_bridge_provisioning_identity_script,
    prove_hms_bridge_provisioning_identity,
)
from .powershell import run_powershell_json


BridgeOAuthProvisioningIdentityError = HmsBridgeProvisioningIdentityError


def build_bridge_oauth_provisioning_identity_script() -> str:
    """Compatibility facade for the shared HMSBridge provisioning identity gate."""

    return build_hms_bridge_provisioning_identity_script()


def prove_bridge_oauth_provisioning_identity() -> dict[str, object]:
    """Compatibility facade preserving existing test/injection semantics."""

    return prove_hms_bridge_provisioning_identity(runner=run_powershell_json)
