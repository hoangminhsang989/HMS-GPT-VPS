from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import dataclass

from .windows_provisioner import HyperVHostState


@dataclass(frozen=True)
class ProbeResult:
    state: HyperVHostState
    raw: dict[str, object]


def _run_powershell(script: str) -> dict[str, object]:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "PowerShell probe failed")
    data = json.loads(completed.stdout)
    if not isinstance(data, dict):
        raise RuntimeError("Unexpected Hyper-V probe payload")
    return data


def probe_hyperv_host() -> ProbeResult:
    """Read Hyper-V readiness without changing host state."""
    if platform.system() != "Windows":
        state = HyperVHostState(False, False, False, False, False)
        return ProbeResult(state=state, raw={"platform": platform.system()})

    script = r'''
$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$pending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
[pscustomobject]@{
  hyperv_available = ($null -ne $feature)
  hyperv_enabled = ($null -ne $feature -and $feature.State -eq 'Enabled')
  virtualization_firmware_enabled = [bool]$cpu.VirtualizationFirmwareEnabled
  restart_required = [bool]$pending
} | ConvertTo-Json -Compress
'''
    raw = _run_powershell(script)
    state = HyperVHostState(
        is_windows=True,
        hyperv_available=bool(raw.get("hyperv_available")),
        hyperv_enabled=bool(raw.get("hyperv_enabled")),
        virtualization_firmware_enabled=bool(raw.get("virtualization_firmware_enabled")),
        restart_required=bool(raw.get("restart_required")),
    )
    return ProbeResult(state=state, raw=raw)
