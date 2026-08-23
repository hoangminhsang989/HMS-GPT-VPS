import base64

import pytest

from hms_gpt_vps.guest_bootstrap import GuestBootstrapConfig, build_guest_foundation_script
from hms_gpt_vps.hyperv_network import HyperVNetworkConfig
from hms_gpt_vps.powershell_direct import (
    PowerShellDirectCredential,
    _MAX_SECRET_PAYLOAD_BYTES,
    _direct_environment,
    build_powershell_direct_host_script,
)


def test_powershell_direct_host_script_contains_no_secret_or_username() -> None:
    credential = PowerShellDirectCredential(
        username="hmsbootstrap",
        password="Aa1!0123456789012345678901234567",
    )
    guest_script = "[pscustomobject]@{ ready = $true }"
    host_script = build_powershell_direct_host_script("HMS-GPT-VPS-01")
    env = _direct_environment(credential, guest_script)

    assert credential.password not in host_script
    assert credential.username not in host_script
    assert guest_script not in host_script
    assert env["HMS_PSDIRECT_PASSWORD"] == credential.password
    assert env["HMS_PSDIRECT_USERNAME"] == credential.username
    assert base64.b64decode(env["HMS_PSDIRECT_SCRIPT_B64"]).decode("utf-8") == guest_script
    assert "HMS_PSDIRECT_PAYLOAD_B64" not in env
    assert credential.password not in repr(credential)


def test_powershell_direct_secret_payload_is_env_only_and_not_host_script() -> None:
    credential = PowerShellDirectCredential(
        username="hmsbootstrap",
        password="Aa1!0123456789012345678901234567",
    )
    guest_script = "param([string]$payloadB64)\n[pscustomobject]@{ ready = $true }"
    payload = b'{"secret":"DEVICE-SECRET-DO-NOT-LOG"}'
    host_script = build_powershell_direct_host_script("HMS-GPT-VPS-01")
    env = _direct_environment(
        credential,
        guest_script,
        secret_payload=payload,
    )

    encoded_payload = base64.b64encode(payload).decode("ascii")
    assert payload.decode("utf-8") not in host_script
    assert encoded_payload not in host_script
    assert env["HMS_PSDIRECT_PAYLOAD_B64"] == encoded_payload
    assert base64.b64decode(env["HMS_PSDIRECT_PAYLOAD_B64"]) == payload
    assert "-ArgumentList $payloadB64" in host_script


def test_powershell_direct_host_script_removes_child_secret_environment_before_invoke() -> None:
    host_script = build_powershell_direct_host_script("HMS-GPT-VPS-01")
    removals = [
        "Remove-Item Env:\\HMS_PSDIRECT_PASSWORD",
        "Remove-Item Env:\\HMS_PSDIRECT_USERNAME",
        "Remove-Item Env:\\HMS_PSDIRECT_SCRIPT_B64",
        "Remove-Item Env:\\HMS_PSDIRECT_PAYLOAD_B64",
    ]
    first_invoke = host_script.index("Invoke-Command -VMName")
    for marker in removals:
        assert marker in host_script
        assert host_script.index(marker) < first_invoke
    assert "-Credential $credential" in host_script


def test_powershell_direct_without_payload_preserves_non_argumentlist_path() -> None:
    host_script = build_powershell_direct_host_script("HMS-GPT-VPS-01")
    assert "if ($hasPayload)" in host_script
    assert "-ArgumentList $payloadB64" in host_script
    assert (
        "Invoke-Command -VMName $vmName -Credential $credential -ScriptBlock $guestScript -ErrorAction Stop"
        in host_script
    )


def test_powershell_direct_rejects_oversize_bootstrap_script() -> None:
    credential = PowerShellDirectCredential(username="hmsbootstrap", password="x" * 32)
    with pytest.raises(ValueError, match="bootstrap limit"):
        _direct_environment(credential, "x" * (17 * 1024))


def test_powershell_direct_rejects_empty_or_oversize_secret_payload() -> None:
    credential = PowerShellDirectCredential(username="hmsbootstrap", password="x" * 32)
    with pytest.raises(ValueError, match="must not be empty"):
        _direct_environment(
            credential,
            "param([string]$payloadB64)\n$true",
            secret_payload=b"",
        )
    with pytest.raises(ValueError, match="payload exceeds"):
        _direct_environment(
            credential,
            "param([string]$payloadB64)\n$true",
            secret_payload=b"x" * (_MAX_SECRET_PAYLOAD_BYTES + 1),
        )


def test_guest_bootstrap_targets_exactly_one_hardware_adapter() -> None:
    script = build_guest_foundation_script(
        GuestBootstrapConfig(network=HyperVNetworkConfig())
    )
    assert "$adapters.Count -ne 1" in script
    assert "HardwareInterface -eq $true" in script
    assert "172.29.240.10" in script
    assert "172.29.240.1" in script
    assert "New-NetIPAddress" in script
    assert "Set-DnsClientServerAddress" in script


def test_guest_bootstrap_protects_workspace_before_agent_service_exists() -> None:
    script = build_guest_foundation_script(
        GuestBootstrapConfig(network=HyperVNetworkConfig())
    )
    assert "C:\\HMS-Workspace" in script
    assert "C:\\ProgramData\\HMS-GPT-VPS" in script
    assert "'/inheritance:r'" in script
    assert "*S-1-5-18:(OI)(CI)F" in script
    assert "*S-1-5-32-544:(OI)(CI)F" in script
    assert "Users:(" not in script
    assert "Everyone:(" not in script
