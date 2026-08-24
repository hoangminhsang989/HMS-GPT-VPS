from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess


_VM_READINESS_KEYS = frozenset({"exists", "state", "heartbeat"})
_MAX_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class VMReadiness:
    exists: bool
    state: str | None
    heartbeat: str | None
    ready: bool

    def validate(self) -> None:
        if not isinstance(self.exists, bool):
            raise ValueError("VM readiness exists must be boolean")
        if self.state is not None and not isinstance(self.state, str):
            raise ValueError("VM readiness state must be a string or null")
        if self.heartbeat is not None and not isinstance(self.heartbeat, str):
            raise ValueError("VM readiness heartbeat must be a string or null")
        if not isinstance(self.ready, bool):
            raise ValueError("VM readiness ready must be boolean")
        if not self.exists and (self.state is not None or self.heartbeat is not None):
            raise ValueError("absent VM readiness must not contain state or heartbeat evidence")
        expected_ready = (
            self.exists
            and self.state == "Running"
            and self.heartbeat in {"OK", "Operating normally"}
        )
        if self.ready is not expected_ready:
            raise ValueError("VM readiness ready flag is inconsistent with evidence")


def _parse_vm_readiness_payload(raw: object) -> VMReadiness:
    if not isinstance(raw, dict):
        raise RuntimeError("VM readiness probe payload must be an object")
    if set(raw) != _VM_READINESS_KEYS:
        raise RuntimeError("VM readiness probe result schema is invalid")

    exists = raw["exists"]
    state = raw["state"]
    heartbeat = raw["heartbeat"]
    if not isinstance(exists, bool):
        raise RuntimeError("VM readiness exists evidence must be boolean")
    if state is not None and not isinstance(state, str):
        raise RuntimeError("VM readiness state evidence must be a string or null")
    if heartbeat is not None and not isinstance(heartbeat, str):
        raise RuntimeError("VM readiness heartbeat evidence must be a string or null")
    if not exists and (state is not None or heartbeat is not None):
        raise RuntimeError("absent VM readiness returned contradictory evidence")

    result = VMReadiness(
        exists=exists,
        state=state,
        heartbeat=heartbeat,
        ready=(
            exists
            and state == "Running"
            and heartbeat in {"OK", "Operating normally"}
        ),
    )
    result.validate()
    return result


def probe_vm_readiness(vm_name: str, timeout_seconds: int = 30) -> VMReadiness:
    if not isinstance(vm_name, str) or not vm_name.strip():
        raise ValueError("vm_name is required")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
        or timeout_seconds > _MAX_TIMEOUT_SECONDS
    ):
        raise ValueError("timeout_seconds must be an integer between 1 and 300")

    escaped = vm_name.replace("'", "''")
    script = f"""
$vm = Get-VM -Name '{escaped}' -ErrorAction SilentlyContinue
if (-not $vm) {{
  [pscustomobject]@{{ exists=[bool]$false; state=$null; heartbeat=$null }} | ConvertTo-Json -Compress
  exit 0
}}
$hb = Get-VMIntegrationService -VMName '{escaped}' -Name 'Heartbeat' -ErrorAction SilentlyContinue
[pscustomobject]@{{
  exists=[bool]$true
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
        result = VMReadiness(False, None, None, False)
        result.validate()
        return result
    try:
        raw = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("VM readiness probe returned invalid JSON") from exc
    return _parse_vm_readiness_payload(raw)
