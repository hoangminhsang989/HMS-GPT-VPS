from __future__ import annotations

from dataclasses import dataclass
import json
import os
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


def ps_literal(value: object) -> str:
    """Return a single-quoted PowerShell literal for untrusted scalar text.

    PowerShell escapes a single quote inside a single-quoted string by doubling
    it. Keeping all generated command arguments behind this helper prevents a
    VM name, path or network label from becoming executable script text.
    """
    text = str(value)
    return "'" + text.replace("'", "''") + "'"


def _child_environment(overrides: Mapping[str, str] | None) -> dict[str, str] | None:
    if overrides is None:
        return None
    merged = dict(os.environ)
    for key, value in overrides.items():
        if not key or "=" in key or "\x00" in key:
            raise ValueError("invalid environment variable name")
        if "\x00" in value:
            raise ValueError("environment variable value contains NUL")
        merged[str(key)] = str(value)
    return merged


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
        env=_child_environment(env),
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


def run_powershell_json(
    script: str,
    *,
    timeout_seconds: int = 60,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    if not script.strip():
        raise ValueError("PowerShell script is required")
    wrapped = (
        "$ErrorActionPreference = 'Stop'\n"
        "$hmsResult = & {\n"
        f"{script}\n"
        "}\n"
        "$hmsResult | ConvertTo-Json -Compress -Depth 8"
    )
    result = run_powershell(
        wrapped,
        timeout_seconds=timeout_seconds,
        env=env,
        check=True,
    )
    text = result.stdout.strip()
    if not text:
        return {}
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise PowerShellError("PowerShell JSON result must be an object")
    return parsed
