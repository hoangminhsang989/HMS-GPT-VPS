from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import uuid

from .hyperv_network import HyperVNetworkConfig
from .powershell import ps_literal, run_powershell_json
from .windows_provisioner import WindowsVMConfig


_HYPERV_OBSERVATION_KEYS = frozenset(
    {
        "network_ready",
        "vm_id",
        "vm_state",
        "vm_switch_ready",
        "install_media_ready",
        "guest_heartbeat_ok",
        "secure_boot_enabled",
        "tpm_enabled",
    }
)
_HYPERV_BOOLEAN_KEYS = (
    "network_ready",
    "vm_switch_ready",
    "install_media_ready",
    "guest_heartbeat_ok",
    "secure_boot_enabled",
    "tpm_enabled",
)


def _canonical_vm_id(value: object, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("Hyper-V VMId must be a canonical GUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("Hyper-V VMId must be a canonical GUID string") from exc
    canonical = str(parsed)
    if value != canonical:
        raise ValueError("Hyper-V VMId must use canonical lowercase GUID form")
    return canonical


def _require_nullable_text(payload: dict[str, object], key: str) -> str | None:
    value = payload[key]
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"Hyper-V observation {key} must be a non-empty string or null")
    return value


@dataclass(frozen=True)
class HyperVObservation:
    network_ready: bool
    vm_id: str | None
    vm_state: str | None
    vm_switch_ready: bool
    install_media_ready: bool
    guest_heartbeat_ok: bool
    secure_boot_enabled: bool = False
    tpm_enabled: bool = False

    @property
    def vm_running(self) -> bool:
        return self.vm_state == "Running"

    @property
    def windows11_security_ready(self) -> bool:
        return self.secure_boot_enabled and self.tpm_enabled


def build_observe_hyperv_script(
    vm_config: WindowsVMConfig,
    network_config: HyperVNetworkConfig,
    *,
    iso_path: Path | None = None,
    expected_vm_id: str | None = None,
) -> str:
    vm_config.validate()
    network_config.validate()
    if expected_vm_id is not None:
        expected_vm_id = _canonical_vm_id(expected_vm_id)

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
$secureBootEnabled = $false
$tpmEnabled = $false

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

  $firmware = Get-VMFirmware -VMName $vmName
  $secureBootEnabled = $firmware.SecureBoot -eq 'On'

  $security = Get-VMSecurity -VMName $vmName
  $tpmEnabled = [bool]$security.TpmEnabled

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
  secure_boot_enabled = [bool]$secureBootEnabled
  tpm_enabled = [bool]$tpmEnabled
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
    if not isinstance(payload, dict) or set(payload) != _HYPERV_OBSERVATION_KEYS:
        raise ValueError("Hyper-V observation result schema is invalid")
    for key in _HYPERV_BOOLEAN_KEYS:
        if not isinstance(payload[key], bool):
            raise ValueError(f"Hyper-V observation {key} must be boolean")

    vm_id_raw = payload["vm_id"]
    vm_id = _canonical_vm_id(vm_id_raw, allow_none=True)
    vm_state = _require_nullable_text(payload, "vm_state")
    if vm_id is None and vm_state is not None:
        raise ValueError("Hyper-V observation cannot report VM state without VMId")
    if vm_id is not None and vm_state is None:
        raise ValueError("Hyper-V observation cannot report VMId without VM state")

    return HyperVObservation(
        network_ready=payload["network_ready"],
        vm_id=vm_id,
        vm_state=vm_state,
        vm_switch_ready=payload["vm_switch_ready"],
        install_media_ready=payload["install_media_ready"],
        guest_heartbeat_ok=payload["guest_heartbeat_ok"],
        secure_boot_enabled=payload["secure_boot_enabled"],
        tpm_enabled=payload["tpm_enabled"],
    )
