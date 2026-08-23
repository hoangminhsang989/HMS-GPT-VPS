from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess


@dataclass(frozen=True)
class VMReadiness:
    exists: bool
    state: str | None
    heartbeat: str | None
    ready: bool


def probe_vm_readiness(vm_name: str, timeout_seconds: int = 30) -> VMReadiness:
    if not vm_name.strip():
        raise ValueError("vm_name is required")

    escaped = vm_name.replace("'", "''")
    script = f"""
$vm = Get-VM -Name '{escaped}' -ErrorAction SilentlyContinue
if (-not $vm) {{
  [pscustomobject]@{{ exists=$false; state=$null; heartbeat=$null }} | ConvertTo-Json -Compress
  exit 0
}}
$hb = Get-VMIntegrationService -VMName '{escaped}' -Name 'Heartbeat' -ErrorAction SilentlyContinue
[pscustomobject]@{{
  exists=$true
  state=[string]$vm.State
  heartbeat=if ($hb) {{ [string]$hb.PrimaryStatusDescription }} else {{ $null }}
}} | ConvertTo-Json -Compress
"""
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        return VMReadiness(False, None, None, False)
    raw = json.loads(completed.stdout.strip())
    state = raw.get("state")
    heartbeat = raw.get("heartbeat")
    ready = bool(raw.get("exists")) and state == "Running" and heartbeat in {"OK", "Operating normally"}
    return VMReadiness(bool(raw.get("exists")), state, heartbeat, ready)
