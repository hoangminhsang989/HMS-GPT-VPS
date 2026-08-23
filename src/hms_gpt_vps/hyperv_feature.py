from __future__ import annotations

from dataclasses import dataclass
import subprocess

from .elevation import ElevationDecision, ElevationRequest, evaluate_elevation


@dataclass(frozen=True)
class HyperVEnableResult:
    attempted: bool
    enabled: bool
    restart_required: bool
    message: str


def enable_hyperv(*, approved: bool, timeout_seconds: int = 600) -> HyperVEnableResult:
    decision = evaluate_elevation(
        ElevationRequest(reason="Enable Hyper-V Windows feature", explicitly_approved=approved)
    )
    if decision is not ElevationDecision.APPROVED:
        return HyperVEnableResult(
            attempted=False,
            enabled=False,
            restart_required=False,
            message="operator approval required",
        )

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart -ErrorAction Stop | ConvertTo-Json -Compress",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    if completed.returncode != 0:
        return HyperVEnableResult(True, False, False, completed.stderr.strip() or "Hyper-V enable failed")

    output = completed.stdout.lower()
    restart_required = "restartneeded" in output and "true" in output
    return HyperVEnableResult(True, True, restart_required, "Hyper-V feature enabled")
