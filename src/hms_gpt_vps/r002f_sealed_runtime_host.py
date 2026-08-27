from __future__ import annotations

import ctypes
import json
import os
import subprocess
from pathlib import Path
from typing import Mapping

from .qualification_file_authority import path_chain_has_redirect


class R002FSealedRuntimeHostError(RuntimeError):
    pass


def system_directory() -> Path:
    if os.name != "nt":
        raise R002FSealedRuntimeHostError(
            "sealed production runtime authority is Windows-only"
        )
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if not isinstance(length, int) or length <= 0 or length >= len(buffer):
        raise R002FSealedRuntimeHostError("could not resolve Windows System32")
    path = Path(buffer.value).absolute()
    if path_chain_has_redirect(path) or not path.is_dir():
        raise R002FSealedRuntimeHostError("Windows System32 authority is invalid")
    return path


def run_system_powershell_json(
    script: str,
    *,
    system_directory: Path,
    timeout_seconds: int = 60,
) -> dict[str, object]:
    host = (
        system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    ).absolute()
    if path_chain_has_redirect(host) or not host.is_file():
        raise R002FSealedRuntimeHostError(
            "OS-backed Windows PowerShell host is invalid"
        )
    wrapped = (
        "$ErrorActionPreference='Stop'\n"
        "try { $r=& {\n" + script + "\n}; "
        "$j=$r|ConvertTo-Json -Compress -Depth 8; "
        "if($null -ne $j){[Console]::Out.Write($j)} } "
        "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n"
        "exit 0"
    )
    completed = subprocess.run(
        [
            str(host),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            wrapped,
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout_seconds,
        env={
            "SystemRoot": str(system_directory.parent),
            "windir": str(system_directory.parent),
            "PATH": str(system_directory),
            "COMSPEC": str(system_directory / "cmd.exe"),
        },
    )
    if completed.returncode != 0:
        raise R002FSealedRuntimeHostError("sealed ACL PowerShell proof failed")
    try:
        value = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise R002FSealedRuntimeHostError(
            "sealed ACL PowerShell proof returned invalid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise R002FSealedRuntimeHostError(
            "sealed ACL PowerShell proof must be an object"
        )
    return value


def sealed_child_environment(
    source: Mapping[str, str],
    *,
    system_directory: Path,
    git_executable: Path | None = None,
) -> dict[str, str]:
    env = {str(k): str(v) for k, v in source.items()}
    for key in list(env):
        upper = key.upper()
        if upper.startswith("PYTHON") or upper.startswith("GIT_"):
            env.pop(key, None)
    system = system_directory.expanduser().absolute()
    powershell_dir = (system / "WindowsPowerShell" / "v1.0").absolute()
    if path_chain_has_redirect(powershell_dir) or not powershell_dir.is_dir():
        raise R002FSealedRuntimeHostError("OS-backed PowerShell directory is invalid")
    path_entries: list[str] = []
    if git_executable is not None:
        path_entries.append(str(git_executable.expanduser().absolute().parent))
    path_entries.extend([str(powershell_dir), str(system)])
    env["PATH"] = os.pathsep.join(path_entries)
    env["SystemRoot"] = str(system.parent)
    env["windir"] = str(system.parent)
    env["COMSPEC"] = str(system / "cmd.exe")
    env["PSModulePath"] = str(
        system / "WindowsPowerShell" / "v1.0" / "Modules"
    )
    env["PYTHONNOUSERSITE"] = "1"
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "NUL"
    env["GIT_CONFIG_COUNT"] = "2"
    env["GIT_CONFIG_KEY_0"] = "core.fsmonitor"
    env["GIT_CONFIG_VALUE_0"] = "false"
    env["GIT_CONFIG_KEY_1"] = "core.untrackedCache"
    env["GIT_CONFIG_VALUE_1"] = "false"
    return env
