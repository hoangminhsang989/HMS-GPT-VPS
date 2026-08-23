from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .windows_provisioner import WindowsVMConfig


@dataclass(frozen=True)
class HyperVExecutionResult:
    changed: bool
    stdout: str


def build_ensure_vm_script(config: WindowsVMConfig) -> str:
    """Return an idempotent PowerShell script for the base VM shell.

    This stage intentionally creates the VM container only. Guest OS image
    installation/bootstrap is handled by a later provisioning phase.
    """
    config.validate()
    vm_dir = config.vm_root / config.name
    vhd_path = vm_dir / f"{config.name}.vhdx"
    return f'''
$ErrorActionPreference = 'Stop'
$changed = $false
$vmName = '{config.name}'
$vmRoot = '{vm_dir}'
$vhdPath = '{vhd_path}'
if (-not (Test-Path $vmRoot)) {{
  New-Item -ItemType Directory -Path $vmRoot -Force | Out-Null
  $changed = $true
}}
$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if ($null -eq $vm) {{
  if (-not (Test-Path $vhdPath)) {{
    New-VHD -Path $vhdPath -Dynamic -SizeBytes {config.disk_size_gb}GB | Out-Null
  }}
  New-VM -Name $vmName -Generation {config.generation} -MemoryStartupBytes {config.memory_mb}MB -VHDPath $vhdPath -Path $vmRoot -SwitchName '{config.switch_name}' | Out-Null
  Set-VMProcessor -VMName $vmName -Count {config.cpu_count}
  Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false
  $changed = $true
}} else {{
  Set-VMProcessor -VMName $vmName -Count {config.cpu_count}
  Set-VMMemory -VMName $vmName -StartupBytes {config.memory_mb}MB -DynamicMemoryEnabled $false
}}
[pscustomobject]@{{ changed = $changed; vm = $vmName }} | ConvertTo-Json -Compress
'''.strip()


def ensure_vm(config: WindowsVMConfig) -> HyperVExecutionResult:
    script = build_ensure_vm_script(config)
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Hyper-V provisioning failed")
    stdout = completed.stdout.strip()
    changed = '"changed":true' in stdout.lower().replace(" ", "")
    return HyperVExecutionResult(changed=changed, stdout=stdout)
