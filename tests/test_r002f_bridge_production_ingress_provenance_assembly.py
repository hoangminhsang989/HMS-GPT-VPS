from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import hms_gpt_vps.bridge_production_assembly as module


def test_production_assembly_uses_ingress_provenance_store_without_parallel_dispatch_path(
    monkeypatch,
) -> None:
    config = module.BridgeProductionConfig(
        runtime_root=Path("runtime"),
        provision_state_path=Path("provision.json"),
        instance_id="instance-01",
        bridge_base_url="https://bridge.example",
        mcp=object(),  # type: ignore[arg-type]
    )
    dependencies = module.BridgeProductionDependencies(
        pairing_exchange_key=object(),  # type: ignore[arg-type]
        request_credential_resolver=lambda *_: None,
        command_credential_resolver=lambda *_: None,
        oauth_token_verifier=object(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(module.BridgeProductionConfig, "validate", lambda self: None)
    monkeypatch.setattr(module.BridgeProductionDependencies, "validate", lambda self: None)
    monkeypatch.setattr(module, "lexical_absolute", lambda value: value)

    layout = SimpleNamespace(
        auth_db_path=Path("auth.sqlite3"),
        presence_db_path=Path("presence.sqlite3"),
        command_db_path=Path("commands.sqlite3"),
        idempotency_db_path=Path("idempotency.sqlite3"),
        pairing_lease_path=Path("pairing-link.dpapi"),
        pairing_issue_lock_path=Path("pairing-issuance.lock"),
        principal_pairing_lock_path=Path("principal-pairing.lock"),
        principal_bindings_dir=Path("principal-bindings"),
    )
    monkeypatch.setattr(module.BridgeRuntimeLayout, "prepare", classmethod(lambda cls, root: layout))

    def marker(name):
        return lambda *args, **kwargs: (name, args, kwargs)

    for name in (
        "ProvisionStateStore",
        "PairingStore",
        "ControlSessionStore",
        "PairingSessionExchange",
        "AgentConnectionRegistry",
        "AgentCommandStore",
        "AgentBridgeService",
        "AgentBridgeHttpBoundary",
        "PairingReadinessConfig",
        "PairingReadinessRuntime",
        "ProvisionStateBoundPrincipalPairingService",
        "PinnedDpapiPrincipalBindingRegistry",
        "IdempotencyStore",
        "ControlGateway",
        "PrincipalAgentControlService",
    ):
        monkeypatch.setattr(module, name, marker(name))
    monkeypatch.setattr(module, "create_dpapi_pairing_link_lease_store", marker("lease"))

    provenance_calls = []

    def provenance_store(idempotency_store):
        value = ("IngressProvenancePrincipalDispatchIntentStore", idempotency_store)
        provenance_calls.append(value)
        return value

    monkeypatch.setattr(
        module,
        "IngressProvenancePrincipalDispatchIntentStore",
        provenance_store,
    )
    monkeypatch.setattr(
        module,
        "PrincipalDispatchIntentStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("legacy dispatch store must not be constructed by production assembly")
        ),
    )
    monkeypatch.setattr(module, "build_hms_mcp_server", marker("mcp_server"))

    result = module.assemble_production_bridge(config, dependencies)

    assert len(provenance_calls) == 1
    assert result.dispatch_intent_store is provenance_calls[0]
    assert result.principal_control[0] == "PrincipalAgentControlService"
    assert result.principal_control[1][3] is result.dispatch_intent_store
    assert result.mcp_server[0] == "mcp_server"
    assert result.mcp_server[1][0] is result.principal_control
