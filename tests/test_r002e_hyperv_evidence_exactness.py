from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.hyperv_network import HyperVNetworkConfig
from hms_gpt_vps.hyperv_observe import observe_hyperv
from hms_gpt_vps.hyperv_vm import reconcile_vm, vhd_path_for
from hms_gpt_vps.windows_provisioner import WindowsVMConfig
from hms_gpt_vps import hyperv_observe as observe_module
from hms_gpt_vps import hyperv_vm as vm_module


VM_ID = "11111111-2222-3333-4444-555555555555"


def _observation_payload() -> dict[str, object]:
    return {
        "network_ready": True,
        "vm_id": VM_ID,
        "vm_state": "Off",
        "vm_switch_ready": True,
        "install_media_ready": False,
        "guest_heartbeat_ok": False,
        "secure_boot_enabled": True,
        "tpm_enabled": True,
    }


def _reconcile_payload(config: WindowsVMConfig) -> dict[str, object]:
    return {
        "changed": False,
        "vm_name": config.name,
        "vm_id": VM_ID,
        "state": "Off",
        "vhd_path": str(vhd_path_for(config)),
        "switch_name": config.switch_name,
        "tpm_enabled": True,
    }


def test_hyperv_observer_rejects_truthy_string_boolean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _observation_payload()
    payload["network_ready"] = "false"
    monkeypatch.setattr(observe_module, "run_powershell_json", lambda *args, **kwargs: payload)

    with pytest.raises(ValueError, match="network_ready.*boolean"):
        observe_hyperv(WindowsVMConfig(), HyperVNetworkConfig())


def test_hyperv_observer_rejects_unknown_result_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _observation_payload()
    payload["unexpected"] = False
    monkeypatch.setattr(observe_module, "run_powershell_json", lambda *args, **kwargs: payload)

    with pytest.raises(ValueError, match="schema"):
        observe_hyperv(WindowsVMConfig(), HyperVNetworkConfig())


@pytest.mark.parametrize(
    "vm_id",
    ["vm-id", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"],
)
def test_hyperv_observer_rejects_noncanonical_vm_id(
    monkeypatch: pytest.MonkeyPatch,
    vm_id: str,
) -> None:
    payload = _observation_payload()
    payload["vm_id"] = vm_id
    monkeypatch.setattr(observe_module, "run_powershell_json", lambda *args, **kwargs: payload)

    with pytest.raises(ValueError, match="VMId"):
        observe_hyperv(WindowsVMConfig(), HyperVNetworkConfig())


def test_hyperv_observer_rejects_vm_state_without_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _observation_payload()
    payload["vm_id"] = None
    monkeypatch.setattr(observe_module, "run_powershell_json", lambda *args, **kwargs: payload)

    with pytest.raises(ValueError, match="state without VMId"):
        observe_hyperv(WindowsVMConfig(), HyperVNetworkConfig())


def test_hyperv_reconcile_rejects_truthy_string_tpm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = WindowsVMConfig()
    payload = _reconcile_payload(config)
    payload["tpm_enabled"] = "true"
    monkeypatch.setattr(vm_module, "run_powershell_json", lambda *args, **kwargs: payload)

    with pytest.raises(ValueError, match="TPM.*boolean"):
        reconcile_vm(config)


def test_hyperv_reconcile_rejects_mismatched_vm_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = WindowsVMConfig()
    payload = _reconcile_payload(config)
    payload["vm_name"] = "OTHER-VM"
    monkeypatch.setattr(vm_module, "run_powershell_json", lambda *args, **kwargs: payload)

    with pytest.raises(ValueError, match="VM name.*mismatch"):
        reconcile_vm(config)


def test_hyperv_reconcile_rejects_noncanonical_vm_id_before_caller_can_persist_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = WindowsVMConfig()
    payload = _reconcile_payload(config)
    payload["vm_id"] = "vm-id"
    monkeypatch.setattr(vm_module, "run_powershell_json", lambda *args, **kwargs: payload)

    with pytest.raises(ValueError, match="VMId"):
        reconcile_vm(config)


def test_hyperv_reconcile_accepts_exact_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = WindowsVMConfig()
    payload = _reconcile_payload(config)
    monkeypatch.setattr(vm_module, "run_powershell_json", lambda *args, **kwargs: payload)

    result = reconcile_vm(config)
    assert result["vm_id"] == VM_ID
    assert result["tpm_enabled"] is True
