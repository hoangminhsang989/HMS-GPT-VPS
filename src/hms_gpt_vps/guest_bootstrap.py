from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from .hyperv_network import HyperVNetworkConfig
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


@dataclass(frozen=True)
class GuestBootstrapConfig:
    network: HyperVNetworkConfig
    workspace_path: str = r"C:\HMS-Workspace"
    runtime_path: str = r"C:\ProgramData\HMS-GPT-VPS"

    def validate(self) -> None:
        self.network.validate()
        if not self.workspace_path.strip():
            raise ValueError("workspace_path is required")
        if not self.runtime_path.strip():
            raise ValueError("runtime_path is required")
        network = IPv4Network(self.network.subnet, strict=True)
        if IPv4Address(self.network.guest_ipv4) not in network:
            raise ValueError("guest IPv4 must be inside managed subnet")


def build_guest_foundation_script(config: GuestBootstrapConfig) -> str:
    """Configure only the dedicated guest NIC and protected HMS directories."""
    config.validate()
    guest_ip = ps_literal(config.network.guest_ipv4)
    gateway = ps_literal(config.network.gateway)
    workspace = ps_literal(config.workspace_path)
    runtime = ps_literal(config.runtime_path)
    prefix_length = config.network.prefix_length
    dns_array = ", ".join(ps_literal(value) for value in config.network.dns_servers)

    return f"""
$ErrorActionPreference = 'Stop'
$guestIp = {guest_ip}
$gateway = {gateway}
$prefixLength = {prefix_length}
$dnsServers = @({dns_array})
$workspace = {workspace}
$runtime = {runtime}

$adapters = @(
  Get-NetAdapter -ErrorAction Stop |
    Where-Object {{ $_.HardwareInterface -eq $true -and $_.Status -ne 'Disabled' }}
)
if ($adapters.Count -ne 1) {{
  throw "Expected exactly one managed guest network adapter; found $($adapters.Count)"
}}
$adapter = $adapters[0]
$ifIndex = $adapter.ifIndex

$currentIp = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object {{ $_.IPAddress -eq $guestIp -and $_.PrefixLength -eq $prefixLength }} |
  Select-Object -First 1
$currentGateway = Get-NetRoute -InterfaceIndex $ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  Where-Object {{ $_.NextHop -eq $gateway }} |
  Select-Object -First 1

if ($null -eq $currentIp -or $null -eq $currentGateway) {{
  Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
  Get-NetRoute -InterfaceIndex $ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $guestIp -PrefixLength $prefixLength -DefaultGateway $gateway -ErrorAction Stop | Out-Null
}}

Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $dnsServers -ErrorAction Stop

foreach ($path in @($workspace, $runtime)) {{
  if (-not (Test-Path -LiteralPath $path)) {{
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }}
  & icacls.exe $path '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) {{
    throw "Failed to set protected ACL on $path"
  }}
}}

$verifiedIp = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object {{ $_.IPAddress -eq $guestIp -and $_.PrefixLength -eq $prefixLength }} |
  Select-Object -First 1
$verifiedGateway = Get-NetRoute -InterfaceIndex $ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
  Where-Object {{ $_.NextHop -eq $gateway }} |
  Select-Object -First 1
$verifiedDns = @(Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
$dnsReady = $true
foreach ($server in $dnsServers) {{
  if ($verifiedDns -notcontains $server) {{ $dnsReady = $false }}
}}

[pscustomobject]@{{
  ready = [bool](
    $null -ne $verifiedIp -and
    $null -ne $verifiedGateway -and
    $dnsReady -and
    (Test-Path -LiteralPath $workspace) -and
    (Test-Path -LiteralPath $runtime)
  )
  computer_name = $env:COMPUTERNAME
  adapter_name = $adapter.Name
  interface_index = $ifIndex
  guest_ipv4 = $verifiedIp.IPAddress
  prefix_length = $verifiedIp.PrefixLength
  gateway = $verifiedGateway.NextHop
  dns = $verifiedDns
  workspace = $workspace
  runtime = $runtime
}}
""".strip()


def apply_guest_foundation(
    vm_name: str,
    credential: PowerShellDirectCredential,
    config: GuestBootstrapConfig,
    *,
    timeout_seconds: int = 120,
) -> dict[str, object]:
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_guest_foundation_script(config),
        timeout_seconds=timeout_seconds,
    )
    if not bool(result.get("ready", False)):
        raise RuntimeError("guest network/workspace bootstrap postcondition failed")
    return result
