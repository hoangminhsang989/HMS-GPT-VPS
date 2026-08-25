from pathlib import Path
import hms_gpt_vps.bridge_service_dependency_loader as module
from hms_gpt_vps.pairing_exchange import PairingExchangeKey


def test_loader_proves_before_and_after_secret_read(monkeypatch,tmp_path):
    parent=tmp_path/'secrets'; parent.mkdir()
    from hms_gpt_vps.bridge_service_secret_storage import BridgeServiceSecretStorageConfig
    c=BridgeServiceSecretStorageConfig(parent/'service-runtime','S-1-5-80-1-2-3-4-5')
    events=[]
    monkeypatch.setattr(module,'prove_hms_bridge_runtime_identity',lambda sid: events.append('identity') or {'process_sid':sid})
    monkeypatch.setattr(module,'prove_bridge_service_secret_storage',lambda *a,**k: events.append('prove') or {'ready':True})
    key=PairingExchangeKey(b'k'*32)
    monkeypatch.setattr(module.BridgeServicePairingExchangeKeyStore,'load',lambda self: events.append('load') or key)
    deps=module.load_bridge_service_secret_dependencies(c)
    assert events==['identity','prove','load','prove']
    assert deps.pairing_exchange_key==key
    assert callable(deps.request_credential_resolver) and callable(deps.command_credential_resolver)

def test_provision_pairing_key_reconciles_before_and_after(monkeypatch,tmp_path):
    parent=tmp_path/'secrets'; parent.mkdir()
    from hms_gpt_vps.bridge_service_secret_storage import BridgeServiceSecretStorageConfig
    c=BridgeServiceSecretStorageConfig(parent/'service-runtime','S-1-5-80-1-2-3-4-5')
    events=[]
    monkeypatch.setattr(module,'provision_bridge_service_secret_storage',lambda *a,**k: events.append(('acl',k.get('require_pairing_key'))) or {'ready':True})
    key=PairingExchangeKey(b'z'*32)
    monkeypatch.setattr(module.BridgeServicePairingExchangeKeyStore,'load_or_create',lambda self: events.append(('key',None)) or key)
    assert module.provision_bridge_service_pairing_key(c)==key
    assert events==[('acl',False),('key',None),('acl',True)]

def test_loader_does_not_touch_secret_if_runtime_identity_fails(monkeypatch,tmp_path):
    parent=tmp_path/'secrets'; parent.mkdir()
    from hms_gpt_vps.bridge_service_secret_storage import BridgeServiceSecretStorageConfig
    c=BridgeServiceSecretStorageConfig(parent/'service-runtime','S-1-5-80-1-2-3-4-5')
    monkeypatch.setattr(module,'prove_hms_bridge_runtime_identity',lambda sid: (_ for _ in ()).throw(PermissionError('blocked')))
    monkeypatch.setattr(module,'prove_bridge_service_secret_storage',lambda *a,**k: (_ for _ in ()).throw(AssertionError('ACL must not be touched')))
    monkeypatch.setattr(module.BridgeServicePairingExchangeKeyStore,'load',lambda self: (_ for _ in ()).throw(AssertionError('secret must not be read')))
    import pytest
    with pytest.raises(PermissionError):
        module.load_bridge_service_secret_dependencies(c)
