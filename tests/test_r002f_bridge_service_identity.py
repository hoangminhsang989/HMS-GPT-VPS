import pytest

import hms_gpt_vps.bridge_service_identity as module

SID = "S-1-5-80-1-2-3-4-5"


def test_identity_script_checks_both_privileged_groups():
    script = module.build_hms_bridge_process_identity_script()
    assert "S-1-5-32-544" in script
    assert "S-1-5-32-578" in script
    assert "WindowsIdentity]::GetCurrent" in script


def test_identity_proof_accepts_exact_virtual_account(monkeypatch):
    monkeypatch.setattr(module, "run_powershell_json", lambda *a, **k: {
        "process_sid": SID,
        "identity_name": r"NT SERVICE\HMSBridge",
        "dedicated_service_sid": True,
        "administrators_sid_present": False,
        "hyperv_administrators_sid_present": False,
    })
    assert module.prove_hms_bridge_runtime_identity(SID)["process_sid"] == SID


@pytest.mark.parametrize("field", ["administrators_sid_present", "hyperv_administrators_sid_present"])
def test_identity_proof_rejects_privileged_token(monkeypatch, field):
    evidence = {
        "process_sid": SID,
        "identity_name": r"NT SERVICE\HMSBridge",
        "dedicated_service_sid": True,
        "administrators_sid_present": False,
        "hyperv_administrators_sid_present": False,
    }
    evidence[field] = True
    monkeypatch.setattr(module, "run_powershell_json", lambda *a, **k: evidence)
    with pytest.raises(module.HmsBridgeServiceIdentityError):
        module.prove_hms_bridge_runtime_identity(SID)


def test_identity_proof_rejects_wrong_named_virtual_account(monkeypatch):
    monkeypatch.setattr(module, "run_powershell_json", lambda *a, **k: {
        "process_sid": SID,
        "identity_name": r"NT SERVICE\Other",
        "dedicated_service_sid": True,
        "administrators_sid_present": False,
        "hyperv_administrators_sid_present": False,
    })
    with pytest.raises(module.HmsBridgeServiceIdentityError):
        module.prove_hms_bridge_runtime_identity(SID)
