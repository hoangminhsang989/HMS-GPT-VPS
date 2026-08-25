import pytest

import hms_gpt_vps.bridge_service_install as module

SID = "S-1-5-80-1-2-3-4-5"
HASH = "a" * 64
PATH = r"C:\Program Files\HMS-GPT-VPS\Bridge\hms-bridge.exe"


def cfg():
    return module.HmsBridgeServiceInstallConfig(
        binary_path=PATH,
        binary_sha256=HASH,
        expected_service_sid=SID,
    )


def test_install_script_uses_virtual_account_and_demand_start_only():
    script = module.build_hms_bridge_service_install_script(cfg())
    assert r"NT SERVICE\HMSBridge" in script
    assert "'start=' 'demand'" in script
    assert "Start-Service" not in script
    assert "Add-LocalGroupMember" not in script
    assert "net localgroup" not in script.lower()
    assert "service_started = $false" in script
    assert "hyperv_admin_assignment_performed = $false" in script
    assert "Get-FileHash" in script
    assert "Assert-NoReparseChain" in script


def test_config_rejects_non_bridge_executable():
    with pytest.raises(module.HmsBridgeServiceInstallError):
        module.HmsBridgeServiceInstallConfig(
            binary_path=r"C:\x\other.exe",
            binary_sha256=HASH,
            expected_service_sid=SID,
        ).validate()


@pytest.mark.parametrize(
    "bad_path",
    [
        r"\\server\share\hms-bridge.exe",
        r"C:\Program Files\HMS-GPT-VPS\Bridge\..\hms-bridge.exe",
        r"C:/Program Files/HMS-GPT-VPS/Bridge/hms-bridge.exe",
    ],
)
def test_config_rejects_noncanonical_or_nonlocal_path(bad_path):
    with pytest.raises(module.HmsBridgeServiceInstallError):
        module.HmsBridgeServiceInstallConfig(
            binary_path=bad_path,
            binary_sha256=HASH,
            expected_service_sid=SID,
        ).validate()


def test_install_evidence_is_exact(monkeypatch):
    result = {
        "ready": True,
        "created": True,
        "service_name": "HMSBridge",
        "display_name": "HMS GPT VPS Bridge",
        "service_account": r"NT SERVICE\HMSBridge",
        "service_sid": SID,
        "service_sid_type": "UNRESTRICTED",
        "start_mode": "Manual",
        "state": "Stopped",
        "binary_path": PATH,
        "binary_sha256": HASH,
        "service_started": False,
        "administrators_assignment_performed": False,
        "hyperv_admin_assignment_performed": False,
    }
    monkeypatch.setattr(module, "run_powershell_json", lambda *a, **k: result)
    assert module.install_hms_bridge_service_authority(cfg()) == result


def test_install_evidence_rejects_started_service(monkeypatch):
    result = {
        "ready": True,
        "created": False,
        "service_name": "HMSBridge",
        "display_name": "HMS GPT VPS Bridge",
        "service_account": r"NT SERVICE\HMSBridge",
        "service_sid": SID,
        "service_sid_type": "UNRESTRICTED",
        "start_mode": "Manual",
        "state": "Stopped",
        "binary_path": PATH,
        "binary_sha256": HASH,
        "service_started": True,
        "administrators_assignment_performed": False,
        "hyperv_admin_assignment_performed": False,
    }
    monkeypatch.setattr(module, "run_powershell_json", lambda *a, **k: result)
    with pytest.raises(module.HmsBridgeServiceInstallError):
        module.install_hms_bridge_service_authority(cfg())
