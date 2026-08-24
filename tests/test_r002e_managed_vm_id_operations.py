from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import build_agent_package_manifest, write_agent_package_manifest
from hms_gpt_vps.agent_package_transfer import AgentPackageTransferPlan
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.managed_vm_id_operations import (
    build_copy_agent_package_to_staging_by_id_script,
    normalize_managed_vm_id,
    probe_agent_package_ready_by_id,
    probe_guest_service_interface_enabled_by_id,
    restore_guest_service_interface_state_by_id,
    transfer_agent_package_to_guest_by_id,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps import managed_vm_id_operations as managed_ops


VM_ID = "11111111-2222-3333-4444-555555555555"
VM_NAME = "HMS-GPT-VPS-01"


def make_plan(tmp_path: Path) -> AgentPackageTransferPlan:
    package = tmp_path / "hms-agent"
    package.mkdir()
    (package / "hms-agent.exe").write_bytes(b"entrypoint")
    internal = package / "_internal"
    internal.mkdir()
    (internal / "runtime.dll").write_bytes(b"runtime")
    manifest = build_agent_package_manifest(package, version="0.1.0")
    manifest_path = tmp_path / "hms-agent.manifest.json"
    write_agent_package_manifest(manifest_path, manifest)
    return AgentPackageTransferPlan.create(
        package,
        manifest_path,
        manifest,
        transfer_id="1" * 32,
        ownership_token="2" * 48,
    )


def test_managed_copy_script_targets_exact_vm_object(tmp_path: Path) -> None:
    script = build_copy_agent_package_to_staging_by_id_script(
        VM_ID,
        VM_NAME,
        make_plan(tmp_path),
    )

    assert f"$vmId = [guid]'{VM_ID}'" in script
    assert "Get-VM -Id $vmId -ErrorAction Stop" in script
    assert "$managedVm.Name -ine $expectedVmName" in script
    assert "Get-VMIntegrationService -VM $managedVm" in script
    assert "Enable-VMIntegrationService -VM $managedVm" in script
    assert "Disable-VMIntegrationService -VM $managedVm" in script
    assert "Copy-VMFile -VM $managedVm" in script
    assert "Copy-VMFile -Name" not in script
    assert "Get-VMIntegrationService -VMName" not in script
    assert "Enable-VMIntegrationService -VMName" not in script
    assert "Disable-VMIntegrationService -VMName" not in script


def test_vm_id_normalization_rejects_non_guid() -> None:
    with pytest.raises(ValueError, match="valid GUID"):
        normalize_managed_vm_id("HMS-GPT-VPS-01")


def test_integration_service_probe_and_restore_use_vm_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scripts: list[str] = []

    def fake_run(script: str, *, timeout_seconds: int):  # type: ignore[no-untyped-def]
        scripts.append(script)
        if "restored =" in script:
            return {
                "restored": True,
                "enabled": False,
                "changed": False,
                "vm_id": VM_ID,
            }
        return {"enabled": False, "vm_id": VM_ID}

    monkeypatch.setattr(managed_ops, "run_powershell_json", fake_run)

    assert probe_guest_service_interface_enabled_by_id(VM_ID, VM_NAME) is False
    result = restore_guest_service_interface_state_by_id(VM_ID, VM_NAME, False)
    assert result["restored"] is True
    assert len(scripts) == 2
    for script in scripts:
        assert "Get-VM -Id $vmId -ErrorAction Stop" in script
        assert "Get-VMIntegrationService -VM $managedVm" in script
        assert "-VMName" not in script


def test_integration_restore_rejects_truthy_string_postcondition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        managed_ops,
        "run_powershell_json",
        lambda *args, **kwargs: {
            "restored": "false",
            "enabled": False,
            "changed": False,
            "vm_id": VM_ID,
        },
    )

    with pytest.raises(RuntimeError, match="malformed boolean evidence: restored"):
        restore_guest_service_interface_state_by_id(VM_ID, VM_NAME, False)


def test_package_transfer_dispatches_guest_steps_by_id_and_host_copy_by_vm_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = make_plan(tmp_path)
    guest_calls: list[tuple[str, str]] = []
    host_scripts: list[str] = []

    def fake_guest(
        vm_id: str,
        vm_name: str,
        _credential,
        script: str,
        *,
        timeout_seconds: int,
        **_kwargs: object,
    ) -> dict[str, object]:
        assert vm_id == VM_ID
        assert vm_name == VM_NAME
        guest_calls.append((vm_id, script))
        if "staging_ready" in script:
            return {"staging_ready": True}
        return {
            "published": True,
            "already_published": False,
            "file_count": plan.manifest.file_count,
            "total_size": plan.manifest.total_size,
            "entrypoint_sha256": plan.manifest.sha256,
            "manifest_sha256": plan.manifest_sha256,
            "staging_removed": True,
        }

    def fake_host(script: str, *, timeout_seconds: int):  # type: ignore[no-untyped-def]
        host_scripts.append(script)
        return {
            "copied": True,
            "copied_files": plan.manifest.file_count,
            "manifest_copied": True,
            "vm_id": VM_ID,
        }

    monkeypatch.setattr(managed_ops, "run_vm_powershell_json_by_id", fake_guest)
    monkeypatch.setattr(managed_ops, "run_powershell_json", fake_host)

    result = transfer_agent_package_to_guest_by_id(
        VM_ID,
        VM_NAME,
        PowerShellDirectCredential("hmsbootstrap", "temporary-secret"),
        plan,
    )

    assert result["published"] is True
    assert result["vm_id"] == VM_ID
    assert len(guest_calls) == 2
    assert len(host_scripts) == 1
    assert "Copy-VMFile -VM $managedVm" in host_scripts[0]
    assert "Copy-VMFile -Name" not in host_scripts[0]


def test_package_transfer_rejects_string_integer_copy_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = make_plan(tmp_path)

    def fake_guest(
        _vm_id: str,
        _vm_name: str,
        _credential,
        script: str,
        *,
        timeout_seconds: int,
        **_kwargs: object,
    ) -> dict[str, object]:
        if "staging_ready" in script:
            return {"staging_ready": True}
        raise AssertionError("publication must not run after malformed copy evidence")

    monkeypatch.setattr(managed_ops, "run_vm_powershell_json_by_id", fake_guest)
    monkeypatch.setattr(
        managed_ops,
        "run_powershell_json",
        lambda *args, **kwargs: {
            "copied": True,
            "copied_files": str(plan.manifest.file_count),
            "manifest_copied": True,
            "vm_id": VM_ID,
        },
    )

    with pytest.raises(RuntimeError, match="malformed integer evidence: copied_files"):
        transfer_agent_package_to_guest_by_id(
            VM_ID,
            VM_NAME,
            PowerShellDirectCredential("hmsbootstrap", "temporary-secret"),
            plan,
        )


def test_package_ready_probe_rejects_truthy_non_boolean_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = make_plan(tmp_path)
    monkeypatch.setattr(
        managed_ops,
        "run_vm_powershell_json_by_id",
        lambda *args, **kwargs: {"package_ready": "true"},
    )

    with pytest.raises(RuntimeError, match="malformed boolean evidence: package_ready"):
        probe_agent_package_ready_by_id(
            VM_ID,
            VM_NAME,
            PowerShellDirectCredential("hmsbootstrap", "temporary-secret"),
            AgentServiceConfig(),
            plan.manifest,
        )
