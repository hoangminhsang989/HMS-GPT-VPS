from __future__ import annotations

from collections.abc import Callable

from mcp.server.auth.provider import TokenVerifier

from .bridge_production_service_runtime import (
    BridgeProductionServiceRuntime,
    build_bridge_production_service_runtime,
)
from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    prove_hms_bridge_runtime_identity,
    require_hms_bridge_service_sid,
)
from .bridge_service_runtime_config import (
    BridgeServiceRuntimeConfig,
    load_bridge_service_runtime_config,
)
from .bridge_windows_service_host import run_hms_bridge_windows_service
from .powershell import ps_literal, run_powershell_json


class BridgeServiceEntrypointError(RuntimeError):
    pass


class BridgeOAuthVerifierAuthorityUnavailableError(BridgeServiceEntrypointError):
    pass


RuntimeConfigLoader = Callable[[], BridgeServiceRuntimeConfig]
OAuthVerifierLoader = Callable[[BridgeServiceRuntimeConfig], TokenVerifier]


def resolve_hms_bridge_service_sid() -> str:
    """Resolve the deterministic virtual-account SID without reading runtime secrets."""

    account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    result = run_powershell_json(
        f"""
$ErrorActionPreference = 'Stop'
$accountName = {account}
$account = [System.Security.Principal.NTAccount]::new($accountName)
$sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
[pscustomobject]@{{
  service_account = [string]$accountName
  service_sid = [string]$sid
}}
""".strip(),
        timeout_seconds=30,
    )
    if frozenset(result) != {"service_account", "service_sid"}:
        raise BridgeServiceEntrypointError(
            "HMSBridge virtual-account SID evidence schema is invalid"
        )
    observed_account = result.get("service_account")
    if (
        not isinstance(observed_account, str)
        or observed_account.casefold() != HMS_BRIDGE_SERVICE_ACCOUNT.casefold()
    ):
        raise BridgeServiceEntrypointError(
            "resolved HMSBridge account differs from virtual-account authority"
        )
    try:
        return require_hms_bridge_service_sid(result.get("service_sid"))
    except PermissionError as exc:
        raise BridgeServiceEntrypointError(
            "resolved HMSBridge service SID is invalid"
        ) from exc


def _default_oauth_verifier_loader(
    config: BridgeServiceRuntimeConfig,
) -> TokenVerifier:
    """Fail closed until a reviewed production OAuth verifier authority exists."""

    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise TypeError("config must be a BridgeServiceRuntimeConfig")
    config.validate()
    raise BridgeOAuthVerifierAuthorityUnavailableError(
        "production OAuth token verifier authority is not provisioned"
    )


def build_hms_bridge_runtime_factory(
    expected_service_sid: str,
    *,
    config_loader: RuntimeConfigLoader = load_bridge_service_runtime_config,
    verifier_loader: OAuthVerifierLoader = _default_oauth_verifier_loader,
) -> Callable[[], BridgeProductionServiceRuntime]:
    """Build a lazy factory so SCM identity proof precedes config/secret access."""

    service_sid = require_hms_bridge_service_sid(expected_service_sid)
    if not callable(config_loader):
        raise TypeError("config_loader must be callable")
    if not callable(verifier_loader):
        raise TypeError("verifier_loader must be callable")

    def factory() -> BridgeProductionServiceRuntime:
        # The Windows service host proves the effective process identity before
        # invoking this closure. Re-prove at the config boundary as defense in depth.
        prove_hms_bridge_runtime_identity(service_sid)
        config = config_loader()
        if not isinstance(config, BridgeServiceRuntimeConfig):
            raise BridgeServiceEntrypointError(
                "Bridge runtime config loader returned an invalid config"
            )
        config.validate()
        verifier = verifier_loader(config)
        if not callable(getattr(verifier, "verify_token", None)):
            raise BridgeServiceEntrypointError(
                "OAuth verifier loader returned an invalid TokenVerifier"
            )
        runtime_config = config.to_runtime_config(service_sid)
        return build_bridge_production_service_runtime(
            runtime_config,
            verifier,
        )

    return factory


def run_hms_bridge_service_entrypoint(
    *,
    sid_resolver: Callable[[], str] = resolve_hms_bridge_service_sid,
    config_loader: RuntimeConfigLoader = load_bridge_service_runtime_config,
    verifier_loader: OAuthVerifierLoader = _default_oauth_verifier_loader,
) -> None:
    """Enter SCM without accepting config paths, secrets, or auth material on argv."""

    if not callable(sid_resolver):
        raise TypeError("sid_resolver must be callable")
    service_sid = require_hms_bridge_service_sid(sid_resolver())
    runtime_factory = build_hms_bridge_runtime_factory(
        service_sid,
        config_loader=config_loader,
        verifier_loader=verifier_loader,
    )
    run_hms_bridge_windows_service(
        expected_service_sid=service_sid,
        runtime_factory=runtime_factory,
    )
