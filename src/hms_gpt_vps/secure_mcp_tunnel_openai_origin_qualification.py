from __future__ import annotations

import hashlib
from pathlib import PureWindowsPath
import subprocess

from .powershell import ps_literal, run_powershell_json
from .secure_mcp_tunnel_ingress_generation_qualification import (
    qualify_running_secure_mcp_tunnel_with_ingress_generation,
)


class SecureMcpTunnelOpenAiOriginQualificationError(RuntimeError):
    pass


def _canonical_generation(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise SecureMcpTunnelOpenAiOriginQualificationError("MCP ingress generation is noncanonical")
    return value


def _expected_runtime_argv(evidence: dict[str, object]) -> tuple[str, ...]:
    executable = evidence.get("tunnel_executable_path")
    health_url_path = evidence.get("health_url_path")
    if not isinstance(executable, str) or not isinstance(health_url_path, str):
        raise SecureMcpTunnelOpenAiOriginQualificationError("native tunnel path evidence is invalid")
    return (
        str(PureWindowsPath(executable)),
        "run",
        "--health.listen-addr",
        "127.0.0.1:0",
        "--health.url-file",
        str(PureWindowsPath(health_url_path)),
        "--mcp.startup-wait-timeout",
        "30s",
    )


def _build_command_line_probe(*, process_id: int) -> str:
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise SecureMcpTunnelOpenAiOriginQualificationError("tunnel process id is invalid")
    return f"""
$ErrorActionPreference = 'Stop'
$rows = @(Get-CimInstance Win32_Process -Filter \"ProcessId={process_id}\" -ErrorAction Stop)
if ($rows.Count -ne 1) {{ throw 'Expected exactly one tunnel process for command-line proof' }}
$proc = $rows[0]
if ([string]::IsNullOrWhiteSpace([string]$proc.CommandLine)) {{ throw 'Tunnel command line is unavailable' }}
[pscustomobject]@{{
  process_id = [uint32]$proc.ProcessId
  parent_process_id = [uint32]$proc.ParentProcessId
  executable_path = [string]$proc.ExecutablePath
  command_line = [string]$proc.CommandLine
}}
""".strip()


def _validate_live_launch_profile(
    probe: dict[str, object],
    evidence: dict[str, object],
) -> str:
    if frozenset(probe) != {"process_id", "parent_process_id", "executable_path", "command_line"}:
        raise SecureMcpTunnelOpenAiOriginQualificationError("tunnel command-line evidence schema is invalid")
    for key, evidence_key in (
        ("process_id", "tunnel_process_id"),
        ("parent_process_id", "tunnel_parent_process_id"),
    ):
        if probe.get(key) != evidence.get(evidence_key):
            raise SecureMcpTunnelOpenAiOriginQualificationError(f"tunnel launch evidence differs: {key}")
    executable = probe.get("executable_path")
    expected_executable = evidence.get("tunnel_executable_path")
    if (
        not isinstance(executable, str)
        or not isinstance(expected_executable, str)
        or str(PureWindowsPath(executable)).casefold()
        != str(PureWindowsPath(expected_executable)).casefold()
    ):
        raise SecureMcpTunnelOpenAiOriginQualificationError("tunnel launch executable path differs")
    command_line = probe.get("command_line")
    if not isinstance(command_line, str) or not command_line:
        raise SecureMcpTunnelOpenAiOriginQualificationError("tunnel command line is invalid")
    expected = subprocess.list2cmdline(list(_expected_runtime_argv(evidence)))
    if command_line != expected:
        raise SecureMcpTunnelOpenAiOriginQualificationError("tunnel command line differs from closed OpenAI runtime launch profile")
    return hashlib.sha256(command_line.encode("utf-8")).hexdigest()


def qualify_running_secure_mcp_tunnel_with_openai_origin_profile(
    *,
    service_sid: str,
    service_process_id: int,
) -> dict[str, object]:
    evidence = qualify_running_secure_mcp_tunnel_with_ingress_generation(
        service_sid=service_sid,
        service_process_id=service_process_id,
    )
    executable_sha = evidence.get("tunnel_executable_sha256")
    if (
        not isinstance(executable_sha, str)
        or len(executable_sha) != 64
        or executable_sha != executable_sha.lower()
        or any(char not in "0123456789abcdef" for char in executable_sha)
    ):
        raise SecureMcpTunnelOpenAiOriginQualificationError("live tunnel executable SHA-256 is noncanonical")
    _canonical_generation(evidence.get("mcp_ingress_generation"))
    tunnel_pid = evidence.get("tunnel_process_id")
    if isinstance(tunnel_pid, bool) or not isinstance(tunnel_pid, int) or tunnel_pid <= 0:
        raise SecureMcpTunnelOpenAiOriginQualificationError("live tunnel process id is invalid")
    probe = run_powershell_json(
        _build_command_line_probe(process_id=tunnel_pid),
        timeout_seconds=15,
    )
    launch_sha256 = _validate_live_launch_profile(probe, evidence)
    if "openai_origin_launch_profile_proven" in evidence or "launch_command_line_sha256" in evidence:
        raise SecureMcpTunnelOpenAiOriginQualificationError("base native evidence unexpectedly contains origin launch proof")
    result = dict(evidence)
    result["openai_origin_launch_profile_proven"] = True
    result["launch_command_line_sha256"] = launch_sha256
    return result
