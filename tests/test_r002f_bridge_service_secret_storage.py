from pathlib import Path
import pytest
import hms_gpt_vps.bridge_service_secret_storage as module

SID='S-1-5-80-1-2-3-4-5'

def cfg(tmp_path):
    parent=tmp_path/'secrets'; parent.mkdir()
    return module.BridgeServiceSecretStorageConfig(parent/'service-runtime', SID)

def test_script_has_exact_principals_machine_secret_shape_and_observer_mode(tmp_path):
    c=cfg(tmp_path)
    script=module.build_bridge_service_secret_storage_script(c,reconcile=False)
    assert 'S-1-5-18' in script and 'S-1-5-32-544' in script and SID in script
    assert 'pairing-exchange-key.service-machine.dpapi' in script
    assert 'agent-credentials' in script
    assert 'Synchronize' in script
    assert '$reconcile = $false' in script
    assert 'unknown entries' in script
    assert 'reparse point' in script

def test_instance_credential_filename_is_deterministic_and_nonrevealing(tmp_path):
    a=module.service_agent_credential_filename('HMS-000001')
    b=module.service_agent_credential_filename('HMS-000001')
    assert a==b and a.endswith('.service-machine.dpapi')
    assert 'HMS-000001' not in a
    assert len(a.split('.')[0])==64

def test_runtime_proof_requires_no_reconciliation_and_pairing_key(monkeypatch,tmp_path):
    c=cfg(tmp_path)
    result={
      'ready':True,'changed':False,'root':str(c.authority_root),'credentials_dir':str(c.credentials_dir),
      'pairing_key_path':str(c.pairing_key_path),'pairing_key_present':True,'credential_file_count':1,
      'root_acl_exact':True,'credentials_acl_exact':True,'secret_file_acls_exact':True,
      'unknown_entries_present':False,'reparse_points_present':False,
    }
    monkeypatch.setattr(module,'run_powershell_json',lambda *a,**k: result)
    assert module.prove_bridge_service_secret_storage(c)['pairing_key_present'] is True
    result['changed']=True
    with pytest.raises(module.BridgeServiceSecretStorageError, match='must not reconcile'):
        module.prove_bridge_service_secret_storage(c)

def test_runtime_proof_rejects_missing_pairing_key(monkeypatch,tmp_path):
    c=cfg(tmp_path)
    result={
      'ready':True,'changed':False,'root':str(c.authority_root),'credentials_dir':str(c.credentials_dir),
      'pairing_key_path':str(c.pairing_key_path),'pairing_key_present':False,'credential_file_count':0,
      'root_acl_exact':True,'credentials_acl_exact':True,'secret_file_acls_exact':True,
      'unknown_entries_present':False,'reparse_points_present':False,
    }
    monkeypatch.setattr(module,'run_powershell_json',lambda *a,**k: result)
    with pytest.raises(module.BridgeServiceSecretStorageError, match='pairing-exchange key is not present'):
        module.prove_bridge_service_secret_storage(c, require_pairing_key=True)
