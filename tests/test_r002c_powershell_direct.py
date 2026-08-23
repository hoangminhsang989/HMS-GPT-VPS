import base64

import pytest

from hms_gpt_vps.guest_bootstrap import GuestBootstrapConfig, build_guest_foundation_script
from hms_gpt_vps.hyperv_network import HyperVNetworkConfig
from hms_gpt_vps.powershell_direct import (
    PowerShellDirectCredential,
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
    assert credential.password not in repr(credential)


def test_powershell_direct_host_script_removes_child_secret_environment() -> None:
    host_script = build_powershell_direct_host_script("HMS-GPT-VPS-01")
    assert "Remove-Item Env:\\HMS_PSDIRECT_PASSWORD" in host_script
    assert "Remove-Item Env:\\HMS_PSDIRECT_USERNAME" in host_script
    assert "Remove-Item Env:\\HMS_PSDIRECT_SCRIPT_B64" in host_script
    assert "Invoke-Command -VMName" in host_script
    assert "-Credential $credential" in host_script


def test_powershell_direct_rejects_oversize_bootstrap_script() -> None:
    credential = PowerShellDirectCredential(username="hmsbootstrap", password="x" * 32)
    with pytest.raises(ValueError, match="bootstrap limit"):
        _direct_environment(credential, "x" * (17 * 1024))


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
