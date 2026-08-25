from pathlib import Path
import hms_gpt_vps.bridge_service_machine_secrets as module
from hms_gpt_vps.agent_transport_protocol import AgentDeviceCredential


def test_pairing_store_uses_distinct_magic_and_create_once(tmp_path):
    path=tmp_path/'pairing-exchange-key.service-machine.dpapi'
    store=module.BridgeServicePairingExchangeKeyStore(path, protector=lambda b:b'X'+b, unprotector=lambda b:b[1:])
    first=store.load_or_create()
    second=store.load()
    assert first==second
    raw=path.read_bytes()
    assert raw.startswith(module.SERVICE_PAIRING_KEY_MAGIC)
    assert not raw.startswith(b'HMS-PXK-V1\x00')

def test_service_credential_store_has_distinct_machine_service_scope(tmp_path):
    store=module.BridgeServiceAgentDeviceCredentialStore(tmp_path/'x.service-machine.dpapi', protector=lambda b:b, unprotector=lambda b:b)
    assert store.protection_scope == 'local-machine-service'
    assert store._create_parent is False

def test_credential_resolver_path_is_derived_from_instance_not_device(tmp_path):
    parent=tmp_path/'secrets'; parent.mkdir()
    from hms_gpt_vps.bridge_service_secret_storage import BridgeServiceSecretStorageConfig, service_agent_credential_path
    c=BridgeServiceSecretStorageConfig(parent/'service-runtime','S-1-5-80-1-2-3-4-5')
    # property only; storage need not yet exist for deterministic path construction
    p=service_agent_credential_path(c,'INSTANCE-1')
    assert p.parent.name=='agent-credentials'
    assert 'INSTANCE-1' not in p.name
