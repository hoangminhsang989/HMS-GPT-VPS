from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .hyperv_network import HyperVNetworkConfig
from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


@dataclass(frozen=True)
class HyperVObservation:
    network_ready: bool
    vm_id: str | None
    vm_state: str | None
    vm_switch_ready: bool
    install_media_ready: bool
    guest_heartbeat_ok: bool

    @property
    def vm_running(self) -> bool:
        return self.vm_state == "Running"


def build_observe_hyperv_script(
    vm_config: WindowsVMConfig,
    network_config: HyperVNetworkConfig,
    *,
    iso_path: Path | None = None,
    expected_vm_id: str | None = None,
) -> str:
    vm_config.validate()
    network_config.validate()

    vm_name = ps_literal(vm_config.name)
    switch_name = ps_literal(network_config.switch_name)
    nat_name = ps_literal(network_config.nat_name)
    subnet = ps_literal(network_config.subnet)
    gateway = ps_literal(network_config.gateway)
    expected_id = ps_literal(expected_vm_id) if expected_vm_id else "$null"
    iso = ps_literal(iso_path) if iso_path is not None else "$null"

    return f"""
$ErrorActionPreference = 'Stop'
$vmName = {vm_name}
$switchName = {switch_name}
$natName = {nat_name}
$subnet = {subnet}
$gateway = {gateway}
$expectedVmId = {expected_id}
$isoPath = {iso}

$networkReady = $false
$vmSwitch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
$nat = Get-NetNat -Name $natName -ErrorAction SilentlyContinue
if ($null -ne $vmSwitch -and $vmSwitch.SwitchType -eq 'Internal' -and $null -ne $nat -and $nat.InternalIPInterfaceAddressPrefix -eq $subnet) {{
  $adapter = Get-NetAdapter -Name "vEthernet ($switchName)" -ErrorAction SilentlyContinue
  if ($null -ne $adapter) {{
    $gatewayAddress = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object {{ $_.IPAddress -eq $gateway }} |
      Select-Object -First 1
    $networkReady = $null -ne $gatewayAddress
  }}
}}

$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
$vmId = $null
$vmState = $null
$vmSwitchReady = $false
$installMediaReady = $false
$guestHeartbeatOk = $false

if ($null -ne $vm) {{
  $vmId = $vm.Id.Guid
  $vmState = $vm.State.ToString()
  if ($null -ne $expectedVmId -and $vmId -ne $expectedVmId) {{
    throw "Observed VMId does not match persisted VM identity"
  }}

  $vmAdapter = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue | Select-Object -First 1
  $vmSwitchReady = $null -ne $vmAdapter -and $vmAdapter.SwitchName -eq $switchName

  if ($null -ne $isoPath) {{
    $dvd = Get-VMDvdDrive -VMName $vmName -ErrorAction SilentlyContinue | Select-Object -First 1
    $installMediaReady = $null -ne $dvd -and $dvd.Path -eq $isoPath
  }}

  $heartbeat = Get-VMIntegrationService -VMName $vmName -Name 'Heartbeat' -ErrorAction SilentlyContinue
  if ($null -ne $heartbeat) {{
    $guestHeartbeatOk = $heartbeat.PrimaryStatusDescription -eq 'OK'
  }}
}}

[pscustomobject]@{{
  network_ready = [bool]$networkReady
  vm_id = $vmId
  vm_state = $vmState
  vm_switch_ready = [bool]$vmSwitchReady
  install_media_ready = [bool]$installMediaReady
  guest_heartbeat_ok = [bool]$guestHeartbeatOk
}}
""".strip()


def observe_hyperv(
    vm_config: WindowsVMConfig,
    network_config: HyperVNetworkConfig,
    *,
    iso_path: Path | None = None,
    expected_vm_id: str | None = None,
) -> HyperVObservation:
    payload = run_powershell_json(
        build_observe_hyperv_script(
            vm_config,
            network_config,
            iso_path=iso_path,
            expected_vm_id=expected_vm_id,
        ),
        timeout_seconds=90,
    )
    return HyperVObservation(
        network_ready=bool(payload.get("network_ready", False)),
        vm_id=str(payload["vm_id"]) if payload.get("vm_id") else None,
        vm_state=str(payload["vm_state"]) if payload.get("vm_state") else None,
        vm_switch_ready=bool(payload.get("vm_switch_ready", False)),
        install_media_ready=bool(payload.get("install_media_ready", False)),
        guest_heartbeat_ok=bool(payload.get("guest_heartbeat_ok", False)),
    )
