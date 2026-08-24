from __future__ import annotations

import base64

import pytest

from hms_gpt_vps.powershell_direct import (
    PowerShellDirectCredential,
    build_powershell_direct_host_script,
    run_vm_powershell_json_by_id,
)


VM_ID = "11111111-2222-3333-4444-555555555555"
VM_NAME = "HMS-GPT-VPS-01"


def test_early_bootstrap_name_mode_remains_available() -> None:
    script = build_powershell_direct_host_script(VM_NAME)

    assert "Invoke-Command -VMName $vmName" in script
    assert "Invoke-Command -VMId" not in script
    assert "Get-VM -Id" not in script


def test_managed_mode_resolves_and_invokes_exact_vm_id() -> None:
    script = build_powershell_direct_host_script(VM_NAME, vm_id=VM_ID)

    assert f"$vmId = [guid]'{VM_ID}'" in script
    assert "Get-VM -Id $vmId -ErrorAction Stop" in script
    assert "PowerShell Direct VMId resolves to a different VM name" in script
    assert "Invoke-Command -VMId $vmId" in script
    assert "Invoke-Command -VMName $vmName" not in script


def test_managed_mode_rejects_invalid_vm_id() -> None:
    with pytest.raises(ValueError, match="valid GUID"):
        build_powershell_direct_host_script(VM_NAME, vm_id="not-a-guid")


def test_vm_id_bound_wrapper_does_not_put_credentials_in_host_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(script: str, *, timeout_seconds: int, env):  # type: ignore[no-untyped-def]
        captured["script"] = script
        captured["env"] = env
        return {"ok": True}

    monkeypatch.setattr("hms_gpt_vps.powershell_direct.run_powershell_json", fake_run)
    credential = PowerShellDirectCredential("hmsbootstrap", "bootstrap-secret")

    result = run_vm_powershell_json_by_id(
        VM_ID,
        VM_NAME,
        credential,
        "[pscustomobject]@{ ok = $true }",
    )

    assert result == {"ok": True}
    script = str(captured["script"])
    assert "bootstrap-secret" not in script
    assert "hmsbootstrap" not in script
    assert "Invoke-Command -VMId $vmId" in script
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["HMS_PSDIRECT_USERNAME"] == "hmsbootstrap"
    assert env["HMS_PSDIRECT_PASSWORD"] == "bootstrap-secret"
    assert env["HMS_PSDIRECT_PAYLOAD_B64"] == ""


def test_no_payload_call_explicitly_shadows_stale_parent_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setenv(
        "HMS_PSDIRECT_PAYLOAD_B64",
        base64.b64encode(b"stale-secret").decode("ascii"),
    )

    def fake_run(script: str, *, timeout_seconds: int, env):  # type: ignore[no-untyped-def]
        captured["env"] = env
        return {"ok": True}

    monkeypatch.setattr("hms_gpt_vps.powershell_direct.run_powershell_json", fake_run)
    run_vm_powershell_json_by_id(
        VM_ID,
        VM_NAME,
        PowerShellDirectCredential("hmsbootstrap", "bootstrap-secret"),
        "[pscustomobject]@{ ok = $true }",
    )

    env = captured["env"]
    assert isinstance(env, dict)
    assert env["HMS_PSDIRECT_PAYLOAD_B64"] == ""


def test_new_secret_payload_replaces_empty_shadow_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(script: str, *, timeout_seconds: int, env):  # type: ignore[no-untyped-def]
        captured["env"] = env
        return {"ok": True}

    monkeypatch.setattr("hms_gpt_vps.powershell_direct.run_powershell_json", fake_run)
    payload = b"fresh-secret"
    run_vm_powershell_json_by_id(
        VM_ID,
        VM_NAME,
        PowerShellDirectCredential("hmsbootstrap", "bootstrap-secret"),
        "param([string]$payloadB64)\n[pscustomobject]@{ ok = $true }",
        secret_payload=payload,
    )

    env = captured["env"]
    assert isinstance(env, dict)
    assert env["HMS_PSDIRECT_PAYLOAD_B64"] == base64.b64encode(payload).decode("ascii")
