from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess
from typing import Mapping


@dataclass(frozen=True)
class PowerShellResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class PowerShellError(RuntimeError):
    pass


def run_powershell(
    script: str,
    *,
    timeout_seconds: int = 60,
    env: Mapping[str, str] | None = None,
    check: bool = False,
) -> PowerShellResult:
    if not script.strip():
        raise ValueError("PowerShell script is required")
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "-",
        ],
        input=script,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        env=dict(env) if env is not None else None,
        check=False,
    )
    result = PowerShellResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    if check and not result.ok:
        raise PowerShellError(
            f"PowerShell failed with exit code {result.returncode}: {result.stderr.strip()}"
        )
    return result


def run_powershell_json(script: str, *, timeout_seconds: int = 60) -> dict[str, object]:
    wrapped = f"$ErrorActionPreference = 'Stop'\n{script}\n| ConvertTo-Json -Compress"
    result = run_powershell(wrapped, timeout_seconds=timeout_seconds, check=True)
    text = result.stdout.strip()
    if not text:
        return {}
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise PowerShellError("PowerShell JSON result must be an object")
    return parsed
