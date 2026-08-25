from __future__ import annotations

from dataclasses import dataclass

from .agent_bridge_service import CommandCredentialResolver, RequestCredentialResolver
from .agent_transport_protocol import AgentDeviceCredential
from .bridge_service_identity import prove_hms_bridge_runtime_identity
from .bridge_service_machine_secrets import (
    BridgeServiceAgentCredentialResolver,
    BridgeServiceAgentDeviceCredentialStore,
    BridgeServicePairingExchangeKeyStore,
)
from .bridge_service_secret_storage import (
    BridgeServiceSecretStorageConfig,
    prove_bridge_service_secret_storage,
    provision_bridge_service_secret_storage,
    service_agent_credential_path,
)
from .pairing_exchange import PairingExchangeKey


@dataclass(frozen=True)
class BridgeServiceSecretDependencies:
    pairing_exchange_key: PairingExchangeKey
    request_credential_resolver: RequestCredentialResolver
    command_credential_resolver: CommandCredentialResolver

    def validate(self) -> None:
        if not isinstance(self.pairing_exchange_key, PairingExchangeKey):
            raise TypeError("pairing_exchange_key must be a PairingExchangeKey")
        if not callable(self.request_credential_resolver):
            raise TypeError("request_credential_resolver must be callable")
        if not callable(self.command_credential_resolver):
            raise TypeError("command_credential_resolver must be callable")


def provision_bridge_service_pairing_key(
    config: BridgeServiceSecretStorageConfig,
) -> PairingExchangeKey:
    provision_bridge_service_secret_storage(config, require_pairing_key=False)
    key = BridgeServicePairingExchangeKeyStore(config.pairing_key_path).load_or_create()
    provision_bridge_service_secret_storage(config, require_pairing_key=True)
    return key


def provision_bridge_service_agent_credential(
    config: BridgeServiceSecretStorageConfig,
    credential: AgentDeviceCredential,
) -> AgentDeviceCredential:
    credential.validate()
    provision_bridge_service_secret_storage(config, require_pairing_key=False)
    path = service_agent_credential_path(config, credential.instance_id)
    stored = BridgeServiceAgentDeviceCredentialStore(path).save_create_only(credential)
    provision_bridge_service_secret_storage(config, require_pairing_key=False)
    return stored


def load_bridge_service_secret_dependencies(
    config: BridgeServiceSecretStorageConfig,
) -> BridgeServiceSecretDependencies:
    """Load only after exact runtime-identity and read-only ACL proof."""
    prove_hms_bridge_runtime_identity(config.bridge_reader_sid)
    prove_bridge_service_secret_storage(config, require_pairing_key=True)
    key = BridgeServicePairingExchangeKeyStore(config.pairing_key_path).load()
    resolver = BridgeServiceAgentCredentialResolver(config)
    # Re-prove after the first secret read so startup cannot publish dependencies
    # if the storage authority changed across the load boundary.
    prove_bridge_service_secret_storage(config, require_pairing_key=True)
    dependencies = BridgeServiceSecretDependencies(
        pairing_exchange_key=key,
        request_credential_resolver=resolver.for_request,
        command_credential_resolver=resolver.for_command,
    )
    dependencies.validate()
    return dependencies
