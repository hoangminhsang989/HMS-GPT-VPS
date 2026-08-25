from __future__ import annotations

import pytest

import hms_gpt_vps.bridge_oauth_provisioning_identity as mod


SID = "S-1-5-80-1-2-3-4-5"


def evidence(**overrides):
    data = {
        "elevated_administrator": True,
        "process_sid": "S-1-5-21-1000",
        "identity_name": r"HOST\Admin",
        "service_name": "HMSBridge",
        "service_start_name": r"NT SERVICE\HMSBridge",
        "service_start_mode": "Manual",
        "service_state": "Stopped",
        "service_sid": SID,
    }
    data.update(overrides)
    return data


def test_script_checks_effective_admin_and_scm_state():
    script = mod.build_bridge_oauth_provisioning_identity_script()
    assert "IsInRole" in script
    assert "WindowsBuiltInRole]::Administrator" in script
    assert "Win32_Service" in script
    assert "HMSBridge" in script


def test_proof_accepts_exact_elevated_stopped_manual_authority(monkeypatch):
    monkeypatch.setattr(mod, "run_powershell_json", lambda *a, **k: evidence())
    result = mod.prove_bridge_oauth_provisioning_identity()
    assert result["service_sid"] == SID


@pytest.mark.parametrize(
    "overrides",
    [
        {"elevated_administrator": False},
        {"process_sid": SID},
        {"identity_name": r"NT SERVICE\HMSBridge"},
        {"service_start_name": r"LocalSystem"},
        {"service_start_mode": "Auto"},
        {"service_state": "Running"},
    ],
)
def test_proof_rejects_privilege_or_scm_drift(monkeypatch, overrides):
    monkeypatch.setattr(
        mod, "run_powershell_json", lambda *a, **k: evidence(**overrides)
    )
    with pytest.raises(mod.BridgeOAuthProvisioningIdentityError):
        mod.prove_bridge_oauth_provisioning_identity()
