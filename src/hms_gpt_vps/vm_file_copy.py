from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .powershell import ps_literal, run_powershell_json
from .windows_image import sha256_file


@dataclass(frozen=True)
class VMFileArtifact:
    source: Path
    destination: str
    sha256: str

    def validate(self) -> None:
        if not self.source.is_file():
            raise FileNotFoundError(self.source)
        if not self.destination.strip():
            raise ValueError("guest destination path is required")
        if len(self.sha256) != 64:
            raise ValueError("artifact SHA-256 must contain 64 hex characters")
        try:
            int(self.sha256, 16)
        except ValueError as exc:
            raise ValueError("artifact SHA-256 must be hexadecimal") from exc
        if sha256_file(self.source).lower() != self.sha256.lower():
            raise ValueError("host artifact SHA-256 mismatch")


def build_copy_vm_file_script(vm_name: str, artifact: VMFileArtifact) -> str:
    """Copy one verified host artifact into a guest without SMB/host sharing.

    Guest Service Interface is enabled only for the copy window when it was
    previously disabled, and its original enabled state is restored in finally.
    """
    if not vm_name.strip():
        raise ValueError("VM name is required")
    artifact.validate()
    vm = ps_literal(vm_name)
    source = ps_literal(artifact.source.resolve())
    destination = ps_literal(artifact.destination)

    return f"""
$ErrorActionPreference = 'Stop'
$vmName = {vm}
$source = {source}
$destination = {destination}
$integrationName = 'Guest Service Interface'
$service = Get-VMIntegrationService -VMName $vmName -Name $integrationName -ErrorAction Stop
$wasEnabled = [bool]$service.Enabled
$enabledTemporarily = $false
try {{
  if (-not $wasEnabled) {{
    Enable-VMIntegrationService -VMName $vmName -Name $integrationName -ErrorAction Stop
    $enabledTemporarily = $true
  }}
  Copy-VMFile -Name $vmName -SourcePath $source -DestinationPath $destination -FileSource Host -CreateFullPath -Force -ErrorAction Stop
  [pscustomobject]@{{
    copied = $true
    enabled_temporarily = $enabledTemporarily
    source = $source
    destination = $destination
  }}
}} finally {{
  if ($enabledTemporarily) {{
    Disable-VMIntegrationService -VMName $vmName -Name $integrationName -ErrorAction SilentlyContinue
  }}
}}
""".strip()


def copy_vm_file(vm_name: str, artifact: VMFileArtifact) -> dict[str, object]:
    artifact.validate()
    return run_powershell_json(
        build_copy_vm_file_script(vm_name, artifact),
        timeout_seconds=120,
    )
