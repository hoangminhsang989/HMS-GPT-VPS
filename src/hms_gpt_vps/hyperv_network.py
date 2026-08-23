from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from .powershell import ps_literal, run_powershell_json


@dataclass(frozen=True)
class HyperVNetworkConfig:
    switch_name: str = "HMS-GPT-VPS-Internal"
    nat_name: str = "HMS-GPT-VPS-NAT"
    subnet: str = "172.29.240.0/24"
    gateway: str = "172.29.240.1"
    guest_ipv4: str = "172.29.240.10"
    dns_servers: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")

    def validate(self) -> None:
        if not self.switch_name.strip():
            raise ValueError("switch_name is required")
        if not self.nat_name.strip():
            raise ValueError("nat_name is required")
        network = IPv4Network(self.subnet, strict=True)
        gateway = IPv4Address(self.gateway)
        guest = IPv4Address(self.guest_ipv4)
        if network.prefixlen > 30:
            raise ValueError("subnet must leave room for gateway and guest")
        if gateway not in network or gateway in {network.network_address, network.broadcast_address}:
            raise ValueError("gateway must be a usable address inside subnet")
        if guest not in network or guest in {network.network_address, network.broadcast_address}:
            raise ValueError("guest_ipv4 must be a usable address inside subnet")
        if guest == gateway:
            raise ValueError("guest_ipv4 must differ from gateway")
        for dns in self.dns_servers:
            IPv4Address(dns)

    @property
    def prefix_length(self) -> int:
        return IPv4Network(self.subnet, strict=True).prefixlen


def build_ensure_internal_nat_script(config: HyperVNetworkConfig) -> str:
    """Build an idempotent internal-switch + outbound-NAT reconcile script.

    The script intentionally creates no NAT static mappings and exposes no
    inbound guest service. A same-name NAT with a different prefix is treated
    as a conflict and fails closed rather than being silently rewritten.
    """
    config.validate()
    switch = ps_literal(config.switch_name)
    nat = ps_literal(config.nat_name)
    subnet = ps_literal(config.subnet)
    gateway = ps_literal(config.gateway)

    return f"""
$ErrorActionPreference = 'Stop'
$changed = $false
$switchName = {switch}
$natName = {nat}
$subnet = {subnet}
$gateway = {gateway}
$prefixLength = {config.prefix_length}

$vmSwitch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if ($null -eq $vmSwitch) {{
  $vmSwitch = New-VMSwitch -Name $switchName -SwitchType Internal
  $changed = $true
}} elseif ($vmSwitch.SwitchType -ne 'Internal') {{
  throw "Existing switch '$switchName' is not Internal"
}}

$adapter = Get-NetAdapter -Name "vEthernet ($switchName)" -ErrorAction Stop
$gatewayAddress = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object {{ $_.IPAddress -eq $gateway }} |
  Select-Object -First 1
if ($null -eq $gatewayAddress) {{
  New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $gateway -PrefixLength $prefixLength | Out-Null
  $changed = $true
}}

$existingNat = Get-NetNat -Name $natName -ErrorAction SilentlyContinue
if ($null -eq $existingNat) {{
  New-NetNat -Name $natName -InternalIPInterfaceAddressPrefix $subnet | Out-Null
  $changed = $true
}} elseif ($existingNat.InternalIPInterfaceAddressPrefix -ne $subnet) {{
  throw "Existing NAT '$natName' uses a different subnet"
}}

[pscustomobject]@{{
  changed = $changed
  switch_name = $switchName
  nat_name = $natName
  subnet = $subnet
  gateway = $gateway
}}
""".strip()


def ensure_internal_nat(config: HyperVNetworkConfig) -> dict[str, object]:
    return run_powershell_json(build_ensure_internal_nat_script(config), timeout_seconds=90)
