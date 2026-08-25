from __future__ import annotations

import pytest

import hms_gpt_vps.agent_bridge_firewall as firewall_module
from hms_gpt_vps.agent_bridge_firewall import (
    AgentBridgeFirewallConfig,
    AgentBridgeFirewallError,
    build_agent_bridge_firewall_script,
    ensure_agent_bridge_firewall,
)
from hms_gpt_vps.hyperv_network import HyperVNetworkConfig


def config() -> AgentBridgeFirewallConfig:
    return AgentBridgeFirewallConfig(network=HyperVNetworkConfig())


def exact_result(*, created: bool = False) -> dict[str, object]:
    return {
        "ready": True,
        "created": created,
        "display_name": "HMS-GPT-VPS Agent Bridge TLS",
        "direction": "Inbound",
        "action": "Allow",
        "enabled": "True",
        "profile": "Any",
        "policy_store_source_type": "Local",
        "protocol": "TCP",
        "local_port": 9443,
        "remote_port": "Any",
        "local_address": "172.29.240.1",
        "remote_address": "172.29.240.10",
        "interface_alias": "vEthernet (HMS-GPT-VPS-Internal)",
        "edge_traversal_policy": "Block",
    }


def test_firewall_config_binds_exact_internal_interface() -> None:
    authority = config()
    authority.validate()

    assert authority.interface_alias == "vEthernet (HMS-GPT-VPS-Internal)"
    assert authority.port == 9443


def test_firewall_config_rejects_wildcard_switch_alias() -> None:
    authority = AgentBridgeFirewallConfig(
        network=HyperVNetworkConfig(switch_name="HMS-*")
    )
    with pytest.raises(ValueError, match="unsafe"):
        authority.validate()


def test_firewall_script_is_create_or_exact_fail_closed() -> None:
    script = build_agent_bridge_firewall_script(config())

    assert "New-NetFirewallRule" in script
    assert "Remove-NetFirewallRule" not in script
    assert "Set-NetFirewallRule" not in script
    assert "-LocalAddress $localAddress" in script
    assert "-RemoteAddress $remoteAddress" in script
    assert "-InterfaceAlias $interfaceAlias" in script
    assert "-EdgeTraversalPolicy Block" in script
    assert "$localAddress = '172.29.240.1'" in script
    assert "$remoteAddress = '172.29.240.10'" in script
    assert "$interfaceAlias = 'vEthernet (HMS-GPT-VPS-Internal)'" in script


def test_ensure_firewall_accepts_exact_observed_authority(monkeypatch) -> None:
    observed = exact_result(created=True)

    def fake_run(script: str, *, timeout_seconds: int):
        assert timeout_seconds == 60
        assert "Get-NetFirewallRule" in script
        return dict(observed)

    monkeypatch.setattr(firewall_module, "run_powershell_json", fake_run)

    result = ensure_agent_bridge_firewall(config())
    assert result == observed


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ready", "true"),
        ("created", 1),
        ("profile", "Private"),
        ("local_port", True),
        ("local_port", 443),
        ("local_address", "0.0.0.0"),
        ("remote_address", "Any"),
        ("interface_alias", "Any"),
        ("edge_traversal_policy", "Allow"),
    ],
)
def test_ensure_firewall_rejects_inexact_evidence(
    monkeypatch,
    key: str,
    value: object,
) -> None:
    observed = exact_result()
    observed[key] = value

    monkeypatch.setattr(
        firewall_module,
        "run_powershell_json",
        lambda script, *, timeout_seconds: dict(observed),
    )

    with pytest.raises(AgentBridgeFirewallError):
        ensure_agent_bridge_firewall(config())
