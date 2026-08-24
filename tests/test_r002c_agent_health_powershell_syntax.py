from __future__ import annotations

import base64
import os
import subprocess

import pytest

from hms_gpt_vps.agent_health_probe import (
    AgentHealthProbeConfig,
    build_agent_health_probe_script,
)


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser smoke only")
def test_generated_agent_health_probe_parses_in_windows_powershell() -> None:
    source = build_agent_health_probe_script(
        AgentHealthProbeConfig(
            port=8765,
            timeout_seconds=5,
            max_body_bytes=32 * 1024,
        )
    )
    environment = dict(os.environ)
    environment["HMS_TEST_SCRIPT_B64"] = base64.b64encode(
        source.encode("utf-8")
    ).decode("ascii")
    parser = r"""
$source = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String($env:HMS_TEST_SCRIPT_B64)
)
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseInput(
  $source,
  [ref]$tokens,
  [ref]$errors
) | Out-Null
Remove-Item Env:\HMS_TEST_SCRIPT_B64 -ErrorAction SilentlyContinue
if ($errors.Count -gt 0) {
  $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }
  exit 1
}
exit 0
""".strip()

    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            parser,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
