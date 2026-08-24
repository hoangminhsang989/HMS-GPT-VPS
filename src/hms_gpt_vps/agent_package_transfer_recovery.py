from __future__ import annotations

from .agent_package import AgentPackageManifest
from .agent_package_manifest_artifact import (
    canonical_agent_package_manifest_sha256,
    canonical_agent_package_manifest_size,
    managed_agent_package_manifest_path,
)
from .agent_package_powershell import POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION
from .agent_package_transfer import AgentPackageTransferPlan
from .agent_service_install import AgentServiceConfig
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


def build_reset_owned_agent_package_staging_script(
    plan: AgentPackageTransferPlan,
) -> str:
    """Remove only the exact owned staging root from a persisted transfer attempt."""
    plan.validate()
    transfer_root = ps_literal(plan.layout.transfer_root)
    marker_path = ps_literal(plan.layout.ownership_marker_path)
    ownership_token = ps_literal(plan.ownership_token)
    return f"""
$ErrorActionPreference = 'Stop'
$transferRoot = {transfer_root}
$markerPath = {marker_path}
$ownershipToken = {ownership_token}

if (-not (Test-Path -LiteralPath $transferRoot)) {{
  [pscustomobject]@{{ reset = $true; existed = $false; removed = $false }}
  return
}}
if (-not (Test-Path -LiteralPath $transferRoot -PathType Container)) {{
  throw 'Persisted HMS Agent transfer root is not a directory'
}}
$rootItem = Get-Item -LiteralPath $transferRoot -Force -ErrorAction Stop
if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'Persisted HMS Agent transfer root must not be a reparse point'
}}
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {{
  throw 'Persisted HMS Agent transfer ownership marker is missing'
}}
$markerItem = Get-Item -LiteralPath $markerPath -Force -ErrorAction Stop
if (($markerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'Persisted HMS Agent transfer ownership marker must not be a reparse point'
}}
if ([System.IO.File]::ReadAllText($markerPath) -cne $ownershipToken) {{
  throw 'Persisted HMS Agent transfer ownership marker does not match'
}}
Remove-Item -LiteralPath $transferRoot -Recurse -Force -ErrorAction Stop
if (Test-Path -LiteralPath $transferRoot) {{
  throw 'Persisted HMS Agent transfer root still exists after owned reset'
}}
[pscustomobject]@{{ reset = $true; existed = $true; removed = $true }}
""".strip()


def reset_owned_agent_package_staging(
    vm_name: str,
    credential: PowerShellDirectCredential,
    plan: AgentPackageTransferPlan,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_reset_owned_agent_package_staging_script(plan),
        timeout_seconds=timeout_seconds,
    )
    if not bool(result.get("reset", False)):
        raise RuntimeError("owned Agent package staging reset postcondition failed")
    return result


def build_agent_package_ready_probe_script(
    service: AgentServiceConfig,
    manifest: AgentPackageManifest,
) -> str:
    """Read-only proof that final package + canonical manifest are exact."""
    service.validate()
    manifest.validate()
    manifest_path = managed_agent_package_manifest_path(service.agent_root_path)
    manifest_hash = canonical_agent_package_manifest_sha256(manifest)
    manifest_size = canonical_agent_package_manifest_size(manifest)
    return f"""
$ErrorActionPreference = 'Stop'
$packageRoot = {ps_literal(service.package_path)}
$manifestPath = {ps_literal(manifest_path)}
$expectedManifestHash = {ps_literal(manifest_hash)}
$expectedManifestSize = [int64]{manifest_size}

{POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION}

$packageReady = $false
$fileCount = 0
$totalSize = 0
$entrypointHash = $null
if ((Test-Path -LiteralPath $manifestPath -PathType Leaf) -and (Test-Path -LiteralPath $packageRoot -PathType Container)) {{
  $manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
  if (($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    throw 'HMS Agent final manifest must not be a reparse point'
  }}
  if ([int64]$manifestItem.Length -ne $expectedManifestSize) {{
    throw 'HMS Agent final manifest size mismatch'
  }}
  if ((Get-HmsSha256 $manifestPath) -ne $expectedManifestHash) {{
    throw 'HMS Agent final manifest SHA-256 mismatch'
  }}
  $payload = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($manifestPath))
  $proof = Test-HmsAgentPackageTree $packageRoot $payload
  $fileCount = [int]$proof.file_count
  $totalSize = [int64]$proof.total_size
  $entrypointHash = [string]$proof.entrypoint_sha256
  $packageReady = [bool](
    $fileCount -eq {manifest.file_count} -and
    $totalSize -eq {manifest.total_size} -and
    $entrypointHash -eq {ps_literal(manifest.sha256.lower())}
  )
}}
[pscustomobject]@{{
  package_ready = [bool]$packageReady
  file_count = [int]$fileCount
  total_size = [int64]$totalSize
  entrypoint_sha256 = $entrypointHash
  manifest_sha256 = $expectedManifestHash
}}
""".strip()


def probe_agent_package_ready(
    vm_name: str,
    credential: PowerShellDirectCredential,
    service: AgentServiceConfig,
    manifest: AgentPackageManifest,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_agent_package_ready_probe_script(service, manifest),
        timeout_seconds=timeout_seconds,
    )
    if bool(result.get("package_ready", False)):
        if int(result.get("file_count", 0)) != manifest.file_count:
            raise RuntimeError("Agent package-ready file-count proof mismatch")
        if int(result.get("total_size", 0)) != manifest.total_size:
            raise RuntimeError("Agent package-ready total-size proof mismatch")
        if str(result.get("entrypoint_sha256", "")).lower() != manifest.sha256.lower():
            raise RuntimeError("Agent package-ready entrypoint proof mismatch")
    return result
