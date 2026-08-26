from __future__ import annotations

from collections.abc import Callable

from mcp.server.auth.provider import TokenVerifier

from .bridge_oauth_introspection_credential import (
    load_protected_bridge_oauth_introspection_credential,
)
from .bridge_oauth_introspection_verifier import (
    build_bridge_oauth_introspection_verifier_sync,
)
from .bridge_pairing_surface_runtime import (
    BridgePairingSurfaceRuntime,
    build_bridge_pairing_surface_runtime,
)
from .bridge_production_service_runtime import (
    BridgeProductionServiceRuntime,
    build_bridge_production_service_runtime,
)
from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    prove_hms_bridge_runtime_identity,
    require_hms_bridge_service_sid,
)
from .bridge_service_config_storage import (
    load_protected_bridge_service_runtime_config,
)
from .bridge_service_runtime_config import BridgeServiceRuntimeConfig
from .bridge_windows_service_host import run_hms_bridge_windows_service
from .powershell import ps_literal, run_powershell_json


class BridgeServiceEntrypointError(RuntimeError):
    pass


RuntimeConfigLoader = Callable[[], BridgeServiceRuntimeConfig]
OAuthVerifierLoader = Callable[[BridgeServiceRuntimeConfig], TokenVerifier]
RuntimeWrapper = Callable[
    [BridgeProductionServiceRuntime, str],
    BridgePairingSurfaceRuntime,
]


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
    """Load the fixed machine credential and discover the RFC 7662 verifier."""

    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise TypeError("config must be a BridgeServiceRuntimeConfig")
    config.validate()
    credential = load_protected_bridge_oauth_introspection_credential(
        config.mcp_issuer_url,
    )
    return build_bridge_oauth_introspection_verifier_sync(
        credential,
        config.mcp_resource_server_url,
    )


def build_hms_bridge_runtime_factory(
    expected_service_sid: str,
    *,
    config_loader: RuntimeConfigLoader = load_protected_bridge_service_runtime_config,
    verifier_loader: OAuthVerifierLoader = _default_oauth_verifier_loader,
    runtime_wrapper: RuntimeWrapper = build_bridge_pairing_surface_runtime,
) -> Callable[[], BridgePairingSurfaceRuntime]:
    """Build a lazy factory so SCM identity proof precedes config/secret access."""

    service_sid = require_hms_bridge_service_sid(expected_service_sid)
    if not callable(config_loader):
        raise TypeError("config_loader must be callable")
    if not callable(verifier_loader):
        raise TypeError("verifier_loader must be callable")
    if not callable(runtime_wrapper):
        raise TypeError("runtime_wrapper must be callable")

    def factory() -> BridgePairingSurfaceRuntime:
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
        base_runtime = build_bridge_production_service_runtime(
            runtime_config,
            verifier,
        )
        if not isinstance(base_runtime, BridgeProductionServiceRuntime):
            raise BridgeServiceEntrypointError(
                "Bridge production runtime factory returned an invalid runtime"
            )
        wrapped = runtime_wrapper(base_runtime, service_sid)
        if not isinstance(wrapped, BridgePairingSurfaceRuntime):
            raise BridgeServiceEntrypointError(
                "Bridge pairing runtime wrapper returned an invalid runtime"
            )
        return wrapped

    return factory


def run_hms_bridge_service_entrypoint(
    *,
    sid_resolver: Callable[[], str] = resolve_hms_bridge_service_sid,
    config_loader: RuntimeConfigLoader = load_protected_bridge_service_runtime_config,
    verifier_loader: OAuthVerifierLoader = _default_oauth_verifier_loader,
    runtime_wrapper: RuntimeWrapper = build_bridge_pairing_surface_runtime,
) -> None:
    """Enter SCM without accepting config paths, secrets, or auth material on argv."""

    if not callable(sid_resolver):
        raise TypeError("sid_resolver must be callable")
    service_sid = require_hms_bridge_service_sid(sid_resolver())
    runtime_factory = build_hms_bridge_runtime_factory(
        service_sid,
        config_loader=config_loader,
        verifier_loader=verifier_loader,
        runtime_wrapper=runtime_wrapper,
    )
    run_hms_bridge_windows_service(
        expected_service_sid=service_sid,
        runtime_factory=runtime_factory,
    )
