from __future__ import annotations

from dataclasses import dataclass

from .agent_bridge_tls_server import AgentBridgeTlsServerConfig
from .hyperv_network import HyperVNetworkConfig
from .powershell import ps_literal, run_powershell_json


_RULE_DISPLAY_NAME = "HMS-GPT-VPS Agent Bridge TLS"
_DEFAULT_AGENT_TLS_PORT = 9443
_RESULT_KEYS = frozenset(
    {
        "ready",
        "created",
        "display_name",
        "direction",
        "action",
        "enabled",
        "profile",
        "policy_store_source_type",
        "protocol",
        "local_port",
        "remote_port",
        "local_address",
        "remote_address",
        "interface_alias",
        "edge_traversal_policy",
    }
)


class AgentBridgeFirewallError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentBridgeFirewallConfig:
    network: HyperVNetworkConfig
    port: int = _DEFAULT_AGENT_TLS_PORT

    def validate(self) -> None:
        AgentBridgeTlsServerConfig(
            network=self.network,
            port=self.port,
        ).validate()
        switch_name = self.network.switch_name
        if (
            switch_name != switch_name.strip()
            or len(switch_name) > 80
            or any(char in switch_name for char in "*?[]")
            or any(ord(char) < 32 for char in switch_name)
        ):
            raise ValueError(
                "Hyper-V switch name is unsafe for exact firewall interface authority"
            )

    @property
    def interface_alias(self) -> str:
        self.validate()
        return f"vEthernet ({self.network.switch_name})"


def build_agent_bridge_firewall_script(config: AgentBridgeFirewallConfig) -> str:
    config.validate()
    display_name = ps_literal(_RULE_DISPLAY_NAME)
    local_address = ps_literal(config.network.gateway)
    remote_address = ps_literal(config.network.guest_ipv4)
    interface_alias = ps_literal(config.interface_alias)
    local_port = config.port

    return f"""
$ErrorActionPreference = 'Stop'
$displayName = {display_name}
$localAddress = {local_address}
$remoteAddress = {remote_address}
$interfaceAlias = {interface_alias}
$localPort = {local_port}
$created = $false

function Get-HmsAgentBridgeFirewallObservation {{
  $rules = @(Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue)
  if ($rules.Count -eq 0) {{
    return $null
  }}
  if ($rules.Count -ne 1) {{
    throw "Expected exactly one HMS Agent Bridge firewall rule"
  }}

  $rule = $rules[0]
  $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
  $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
  $interfaceFilters = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
  if ($portFilters.Count -ne 1) {{
    throw "Expected exactly one firewall port filter"
  }}
  if ($addressFilters.Count -ne 1) {{
    throw "Expected exactly one firewall address filter"
  }}
  if ($interfaceFilters.Count -ne 1) {{
    throw "Expected exactly one firewall interface filter"
  }}

  $localAddresses = @($addressFilters[0].LocalAddress)
  $remoteAddresses = @($addressFilters[0].RemoteAddress)
  $interfaceAliases = @($interfaceFilters[0].InterfaceAlias)
  $remotePorts = @($portFilters[0].RemotePort)
  if ($localAddresses.Count -ne 1 -or $remoteAddresses.Count -ne 1) {{
    throw "Firewall address authority must contain exactly one local and remote address"
  }}
  if ($interfaceAliases.Count -ne 1) {{
    throw "Firewall interface authority must contain exactly one alias"
  }}
  if ($remotePorts.Count -ne 1) {{
    throw "Firewall remote-port authority must contain exactly one value"
  }}

  $observedPort = 0
  if (-not [int]::TryParse([string]$portFilters[0].LocalPort, [ref]$observedPort)) {{
    throw "Firewall local port is not an exact integer"
  }}
  $protocol = [string]$portFilters[0].Protocol
  if ($protocol -eq '6') {{
    $protocol = 'TCP'
  }}

  return [pscustomobject]@{{
    rule = $rule
    direction = [string]$rule.Direction
    action = [string]$rule.Action
    enabled = [string]$rule.Enabled
    profile = [string]$rule.Profile
    policy_store_source_type = [string]$rule.PolicyStoreSourceType
    protocol = [string]$protocol
    local_port = [int]$observedPort
    remote_port = [string]$remotePorts[0]
    local_address = [string]$localAddresses[0]
    remote_address = [string]$remoteAddresses[0]
    interface_alias = [string]$interfaceAliases[0]
    edge_traversal_policy = [string]$rule.EdgeTraversalPolicy
  }}
}}

$observation = Get-HmsAgentBridgeFirewallObservation
if ($null -eq $observation) {{
  New-NetFirewallRule `
    -DisplayName $displayName `
    -PolicyStore PersistentStore `
    -Direction Inbound `
    -Action Allow `
    -Enabled True `
    -Profile Any `
    -Protocol TCP `
    -LocalPort $localPort `
    -RemotePort Any `
    -LocalAddress $localAddress `
    -RemoteAddress $remoteAddress `
    -InterfaceAlias $interfaceAlias `
    -EdgeTraversalPolicy Block | Out-Null
  $created = $true
  $observation = Get-HmsAgentBridgeFirewallObservation
  if ($null -eq $observation) {{
    throw "Firewall rule was not observable after creation"
  }}
}}

if ($observation.direction -ne 'Inbound') {{
  throw "Existing firewall rule direction differs from authority"
}}
if ($observation.action -ne 'Allow') {{
  throw "Existing firewall rule action differs from authority"
}}
if ($observation.enabled -ne 'True') {{
  throw "Existing firewall rule must be enabled"
}}
if ($observation.profile -ne 'Any') {{
  throw "Existing firewall rule profile differs from authority"
}}
if ($observation.policy_store_source_type -ne 'Local') {{
  throw "Existing firewall rule is not owned by local persistent policy"
}}
if ($observation.protocol -ne 'TCP') {{
  throw "Existing firewall rule protocol differs from authority"
}}
if ($observation.local_port -ne $localPort) {{
  throw "Existing firewall rule local port differs from authority"
}}
if ($observation.remote_port -ne 'Any') {{
  throw "Existing firewall rule remote port differs from authority"
}}
if ($observation.local_address -ne $localAddress) {{
  throw "Existing firewall rule local address differs from authority"
}}
if ($observation.remote_address -ne $remoteAddress) {{
  throw "Existing firewall rule remote address differs from authority"
}}
if ($observation.interface_alias -ne $interfaceAlias) {{
  throw "Existing firewall rule interface differs from authority"
}}
if ($observation.edge_traversal_policy -ne 'Block') {{
  throw "Existing firewall rule edge traversal policy differs from authority"
}}

[pscustomobject]@{{
  ready = $true
  created = [bool]$created
  display_name = [string]$observation.rule.DisplayName
  direction = [string]$observation.direction
  action = [string]$observation.action
  enabled = [string]$observation.enabled
  profile = [string]$observation.profile
  policy_store_source_type = [string]$observation.policy_store_source_type
  protocol = [string]$observation.protocol
  local_port = [int]$observation.local_port
  remote_port = [string]$observation.remote_port
  local_address = [string]$observation.local_address
  remote_address = [string]$observation.remote_address
  interface_alias = [string]$observation.interface_alias
  edge_traversal_policy = [string]$observation.edge_traversal_policy
}}
""".strip()


def _validate_firewall_result(
    result: dict[str, object],
    config: AgentBridgeFirewallConfig,
) -> None:
    if set(result) != _RESULT_KEYS:
        raise AgentBridgeFirewallError("firewall result schema is invalid")
    if result["ready"] is not True:
        raise AgentBridgeFirewallError("firewall postcondition is not ready")
    if not isinstance(result["created"], bool):
        raise AgentBridgeFirewallError("firewall created evidence must be boolean")

    expected_strings = {
        "display_name": _RULE_DISPLAY_NAME,
        "direction": "Inbound",
        "action": "Allow",
        "enabled": "True",
        "profile": "Any",
        "policy_store_source_type": "Local",
        "protocol": "TCP",
        "remote_port": "Any",
        "local_address": config.network.gateway,
        "remote_address": config.network.guest_ipv4,
        "interface_alias": config.interface_alias,
        "edge_traversal_policy": "Block",
    }
    for key, expected in expected_strings.items():
        value = result[key]
        if not isinstance(value, str) or value != expected:
            raise AgentBridgeFirewallError(
                f"firewall {key} evidence differs from exact authority"
            )

    local_port = result["local_port"]
    if (
        not isinstance(local_port, int)
        or isinstance(local_port, bool)
        or local_port != config.port
    ):
        raise AgentBridgeFirewallError(
            "firewall local_port evidence differs from exact authority"
        )


def ensure_agent_bridge_firewall(
    config: AgentBridgeFirewallConfig,
) -> dict[str, object]:
    if not isinstance(config, AgentBridgeFirewallConfig):
        raise TypeError("config must be an AgentBridgeFirewallConfig")
    config.validate()
    result = run_powershell_json(
        build_agent_bridge_firewall_script(config),
        timeout_seconds=60,
    )
    _validate_firewall_result(result, config)
    return result
