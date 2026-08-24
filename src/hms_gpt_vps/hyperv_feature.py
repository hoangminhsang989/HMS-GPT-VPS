from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess

from .elevation import ElevationDecision, ElevationRequest, evaluate_elevation


_HYPERV_ENABLE_RESULT_KEYS = frozenset({"enabled", "restart_required"})
_MAX_ENABLE_TIMEOUT_SECONDS = 1800


@dataclass(frozen=True)
class HyperVEnableResult:
    attempted: bool
    enabled: bool
    restart_required: bool
    message: str

    def validate(self) -> None:
        for name in ("attempted", "enabled", "restart_required"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"Hyper-V enable result must be boolean: {name}")
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError("Hyper-V enable result message is required")
        if not self.attempted and (self.enabled or self.restart_required):
            raise ValueError("unattempted Hyper-V enable result contains positive evidence")


def enable_hyperv(*, approved: bool, timeout_seconds: int = 600) -> HyperVEnableResult:
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
        or timeout_seconds > _MAX_ENABLE_TIMEOUT_SECONDS
    ):
        raise ValueError("timeout_seconds must be an integer between 1 and 1800")

    decision = evaluate_elevation(
        ElevationRequest(reason="Enable Hyper-V Windows feature", explicitly_approved=approved)
    )
    if decision is not ElevationDecision.APPROVED:
        result = HyperVEnableResult(
            attempted=False,
            enabled=False,
            restart_required=False,
            message="operator approval required",
        )
        result.validate()
        return result

    script = r'''
$ErrorActionPreference = 'Stop'
$enableResult = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart -ErrorAction Stop
$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
[pscustomobject]@{
  enabled = [bool]($feature.State -eq 'Enabled')
  restart_required = [bool]$enableResult.RestartNeeded
} | ConvertTo-Json -Compress
'''
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        result = HyperVEnableResult(
            attempted=True,
            enabled=False,
            restart_required=False,
            message=completed.stderr.strip() or "Hyper-V enable failed",
        )
        result.validate()
        return result

    try:
        payload = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("Hyper-V enable returned invalid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != _HYPERV_ENABLE_RESULT_KEYS:
        raise RuntimeError("Hyper-V enable result schema is invalid")
    for key in _HYPERV_ENABLE_RESULT_KEYS:
        if not isinstance(payload[key], bool):
            raise RuntimeError(f"Hyper-V enable {key} evidence must be boolean")
    if payload["enabled"] is not True:
        raise RuntimeError("Hyper-V enable command completed without enabled readback proof")

    result = HyperVEnableResult(
        attempted=True,
        enabled=True,
        restart_required=payload["restart_required"],
        message="Hyper-V feature enabled",
    )
    result.validate()
    return result
