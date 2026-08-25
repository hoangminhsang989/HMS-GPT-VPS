from __future__ import annotations

import pytest

import hms_gpt_vps.bridge_service_provisioning_identity as mod


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


def test_script_checks_elevated_admin_and_exact_quiescent_service():
    script = mod.build_hms_bridge_provisioning_identity_script()
    assert "IsInRole" in script
    assert "WindowsBuiltInRole]::Administrator" in script
    assert "Expected exactly one HMSBridge SCM service" in script
    assert "HMSBridge" in script


def test_proof_accepts_exact_staging_authority():
    result = mod.prove_hms_bridge_provisioning_identity(
        runner=lambda *a, **k: evidence()
    )
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
def test_proof_rejects_privilege_or_scm_drift(overrides):
    with pytest.raises(mod.HmsBridgeProvisioningIdentityError):
        mod.prove_hms_bridge_provisioning_identity(
            runner=lambda *a, **k: evidence(**overrides)
        )
