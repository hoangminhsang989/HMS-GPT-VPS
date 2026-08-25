from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_transport_protocol import AgentDeviceCredential
from hms_gpt_vps.bridge_production_assembly import (
    BridgeProductionAssemblyError,
    BridgeProductionConfig,
    BridgeProductionDependencies,
    BridgeRuntimeLayout,
    assemble_production_bridge,
)
from hms_gpt_vps.mcp_bridge_server import HmsMcpBridgeConfig
from hms_gpt_vps.pairing_exchange import PairingExchangeKey
from hms_gpt_vps.principal_binding_registry_authority import (
    PinnedDpapiPrincipalBindingRegistry,
)


INSTANCE_ID = "hms-prod-01"


class StubTokenVerifier:
    async def verify_token(self, token: str):
        return None


def prepare_runtime_root(tmp_path: Path) -> Path:
    root = tmp_path / "bridge"
    (root / "db").mkdir(parents=True)
    (root / "secrets" / "principal-bindings").mkdir(parents=True)
    (root / "locks").mkdir(parents=True)
    return root


def build_config(tmp_path: Path) -> BridgeProductionConfig:
    root = prepare_runtime_root(tmp_path)
    provision_parent = tmp_path / "host-state"
    provision_parent.mkdir()
    return BridgeProductionConfig(
        runtime_root=root,
        provision_state_path=provision_parent / "provision.json",
        instance_id=INSTANCE_ID,
        bridge_base_url="https://bridge.example",
        mcp=HmsMcpBridgeConfig(
            issuer_url="https://issuer.example",
            resource_server_url="https://resource.example",
            port=8765,
        ),
    )


def build_dependencies() -> BridgeProductionDependencies:
    credential = AgentDeviceCredential(
        instance_id=INSTANCE_ID,
        device_id="device-01",
        secret=b"S" * 32,
    )

    def request_resolver(
        instance_id: str,
        device_id: str,
    ) -> AgentDeviceCredential:
        if instance_id != INSTANCE_ID or device_id != credential.device_id:
            raise KeyError("unknown Agent")
        return credential

    def command_resolver(instance_id: str) -> AgentDeviceCredential:
        if instance_id != INSTANCE_ID:
            raise KeyError("unknown Agent")
        return credential

    return BridgeProductionDependencies(
        pairing_exchange_key=PairingExchangeKey(b"K" * 32),
        request_credential_resolver=request_resolver,
        command_credential_resolver=command_resolver,
        oauth_token_verifier=StubTokenVerifier(),
    )


def test_layout_requires_precreated_fixed_directories(tmp_path: Path) -> None:
    root = tmp_path / "bridge"
    root.mkdir()
    (root / "db").mkdir()
    (root / "secrets").mkdir()

    with pytest.raises(FileNotFoundError):
        BridgeRuntimeLayout.prepare(root)

    assert not (root / "locks").exists()
    assert not (root / "secrets" / "principal-bindings").exists()


def test_layout_rejects_redirected_principal_binding_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bridge"
    (root / "db").mkdir(parents=True)
    (root / "secrets").mkdir()
    (root / "locks").mkdir()
    real = tmp_path / "elsewhere"
    real.mkdir()
    link = root / "secrets" / "principal-bindings"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(PermissionError):
        BridgeRuntimeLayout.prepare(root)


def test_production_assembly_wires_exact_shared_authorities(
    tmp_path: Path,
) -> None:
    config = build_config(tmp_path)
    dependencies = build_dependencies()
    assembly = assemble_production_bridge(config, dependencies)

    assert assembly.readiness.pairing_store is assembly.pairing_store
    assert assembly.readiness.presence_reader is assembly.presence_registry
    assert assembly.pairing_exchange.pairing_store is assembly.pairing_store
    assert assembly.pairing_exchange.session_store is assembly.session_store
    assert assembly.principal_pairing.readiness is assembly.readiness
    assert isinstance(
        assembly.principal_pairing.binding_registry,
        PinnedDpapiPrincipalBindingRegistry,
    )
    assert assembly.principal_pairing.exchange is assembly.pairing_exchange
    assert assembly.agent_bridge.registry is assembly.presence_registry
    assert assembly.agent_bridge.commands is assembly.command_store
    assert assembly.agent_http.service is assembly.agent_bridge
    assert assembly.gateway.session_store is assembly.session_store
    assert assembly.gateway.idempotency_store is assembly.idempotency_store
    assert (
        assembly.dispatch_intent_store.idempotency_store
        is assembly.idempotency_store
    )
    assert (
        assembly.principal_control.principal_pairing
        is assembly.principal_pairing
    )
    assert assembly.principal_control.gateway is assembly.gateway
    assert assembly.principal_control.agent_bridge is assembly.agent_bridge
    assert (
        assembly.principal_control.intent_store
        is assembly.dispatch_intent_store
    )

    assert assembly.layout.auth_db_path.exists()
    assert assembly.layout.presence_db_path.exists()
    assert assembly.layout.command_db_path.exists()
    assert assembly.layout.idempotency_db_path.exists()
    assert not assembly.layout.pairing_lease_path.exists()


def test_assembly_rejects_redirected_provision_authority(
    tmp_path: Path,
) -> None:
    root = prepare_runtime_root(tmp_path)
    actual_parent = tmp_path / "actual-state"
    actual_parent.mkdir()
    redirect_parent = tmp_path / "state-link"
    try:
        redirect_parent.symlink_to(actual_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    config = BridgeProductionConfig(
        runtime_root=root,
        provision_state_path=redirect_parent / "provision.json",
        instance_id=INSTANCE_ID,
        bridge_base_url="https://bridge.example",
        mcp=HmsMcpBridgeConfig(
            issuer_url="https://issuer.example",
            resource_server_url="https://resource.example",
        ),
    )
    with pytest.raises(BridgeProductionAssemblyError):
        assemble_production_bridge(config, build_dependencies())


def test_layout_paths_are_fixed_and_secret_files_are_not_precreated(
    tmp_path: Path,
) -> None:
    root = prepare_runtime_root(tmp_path)
    layout = BridgeRuntimeLayout.prepare(root)

    assert layout.db_dir == root / "db"
    assert layout.secrets_dir == root / "secrets"
    assert layout.locks_dir == root / "locks"
    assert (
        layout.principal_bindings_dir
        == root / "secrets" / "principal-bindings"
    )
    assert layout.auth_db_path.name == "pairing-control.sqlite3"
    assert layout.pairing_lease_path.name == "pairing-link.dpapi"
    assert not layout.pairing_lease_path.exists()
