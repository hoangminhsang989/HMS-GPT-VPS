from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from pathlib import PureWindowsPath

from .hyperv_network import HyperVNetworkConfig
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


_GUEST_FOUNDATION_RESULT_KEYS = frozenset(
    {
        "ready",
        "computer_name",
        "adapter_name",
        "interface_index",
        "guest_ipv4",
        "prefix_length",
        "gateway",
        "dns",
        "workspace",
        "runtime",
    }
)
_MAX_BOOTSTRAP_TIMEOUT_SECONDS = 600


def _same_windows_path(left: str, right: str) -> bool:
    return str(PureWindowsPath(left)).casefold() == str(PureWindowsPath(right)).casefold()


@dataclass(frozen=True)
class GuestBootstrapConfig:
    network: HyperVNetworkConfig
    workspace_path: str = r"C:\HMS-Workspace"
    runtime_path: str = r"C:\ProgramData\HMS-GPT-VPS"

    def validate(self) -> None:
        self.network.validate()
        if not isinstance(self.workspace_path, str) or not self.workspace_path.strip():
            raise ValueError("workspace_path is required")
        if not isinstance(self.runtime_path, str) or not self.runtime_path.strip():
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
$verifiedDns = @((Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
$dnsReady = $verifiedDns.Count -eq $dnsServers.Count
if ($dnsReady) {{
  for ($index = 0; $index -lt $dnsServers.Count; $index += 1) {{
    if ($verifiedDns[$index] -ne $dnsServers[$index]) {{
      $dnsReady = $false
      break
    }}
  }}
}}

[pscustomobject]@{{
  ready = [bool](
    $null -ne $verifiedIp -and
    $null -ne $verifiedGateway -and
    $dnsReady -and
    (Test-Path -LiteralPath $workspace) -and
    (Test-Path -LiteralPath $runtime)
  )
  computer_name = [string]$env:COMPUTERNAME
  adapter_name = [string]$adapter.Name
  interface_index = [int]$ifIndex
  guest_ipv4 = [string]$verifiedIp.IPAddress
  prefix_length = [int]$verifiedIp.PrefixLength
  gateway = [string]$verifiedGateway.NextHop
  dns = @($verifiedDns)
  workspace = [string]$workspace
  runtime = [string]$runtime
}}
""".strip()


def _validate_guest_foundation_result(
    result: dict[str, object],
    config: GuestBootstrapConfig,
) -> None:
    if set(result) != _GUEST_FOUNDATION_RESULT_KEYS:
        raise RuntimeError("guest bootstrap result schema is invalid")
    if result["ready"] is not True:
        raise RuntimeError("guest network/workspace bootstrap postcondition failed")

    for key in ("computer_name", "adapter_name"):
        value = result[key]
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"guest bootstrap {key} evidence is invalid")

    interface_index = result["interface_index"]
    if (
        not isinstance(interface_index, int)
        or isinstance(interface_index, bool)
        or interface_index <= 0
    ):
        raise RuntimeError("guest bootstrap interface_index evidence is invalid")

    prefix_length = result["prefix_length"]
    if (
        not isinstance(prefix_length, int)
        or isinstance(prefix_length, bool)
        or prefix_length != config.network.prefix_length
    ):
        raise RuntimeError("guest bootstrap prefix_length evidence differs from config")

    if result["guest_ipv4"] != config.network.guest_ipv4:
        raise RuntimeError("guest bootstrap IPv4 evidence differs from config")
    if result["gateway"] != config.network.gateway:
        raise RuntimeError("guest bootstrap gateway evidence differs from config")

    dns = result["dns"]
    if not isinstance(dns, list) or any(not isinstance(value, str) for value in dns):
        raise RuntimeError("guest bootstrap DNS evidence must be a list of strings")
    if tuple(dns) != tuple(config.network.dns_servers):
        raise RuntimeError("guest bootstrap DNS evidence differs from exact managed config")

    workspace = result["workspace"]
    runtime = result["runtime"]
    if not isinstance(workspace, str) or not _same_windows_path(
        workspace, config.workspace_path
    ):
        raise RuntimeError("guest bootstrap workspace evidence differs from config")
    if not isinstance(runtime, str) or not _same_windows_path(runtime, config.runtime_path):
        raise RuntimeError("guest bootstrap runtime evidence differs from config")


def apply_guest_foundation(
    vm_name: str,
    credential: PowerShellDirectCredential,
    config: GuestBootstrapConfig,
    *,
    timeout_seconds: int = 120,
) -> dict[str, object]:
    if not isinstance(vm_name, str) or not vm_name.strip():
        raise ValueError("vm_name is required")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
        or timeout_seconds > _MAX_BOOTSTRAP_TIMEOUT_SECONDS
    ):
        raise ValueError("timeout_seconds must be an integer between 1 and 600")
    credential.validate()
    config.validate()
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_guest_foundation_script(config),
        timeout_seconds=timeout_seconds,
    )
    _validate_guest_foundation_result(result, config)
    return result
