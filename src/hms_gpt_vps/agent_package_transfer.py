from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
from pathlib import Path, PureWindowsPath
import secrets
import uuid

from .agent_package import (
    AgentPackageManifest,
    load_agent_package_manifest,
    verify_agent_package,
)
from .agent_package_powershell import POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION
from .agent_service_install import AgentServiceConfig
from .powershell import ps_literal, run_powershell_json
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json
from .powershell_sha256 import POWERSHELL_SHA256_FUNCTION
from .windows_image import sha256_file


_TRANSFER_ID_HEX_LENGTH = 32
_OWNERSHIP_TOKEN_HEX_LENGTH = 48
_MAX_HOST_COPY_SCRIPT_BYTES = 24 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_STAGING_MARKER_NAME = ".hms-agent-package-transfer-owned"
_MANIFEST_FILENAME = "hms-agent.manifest.json"


def _validate_lower_hex(value: str, *, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or value != value.lower():
        raise ValueError(f"{label} must contain exactly {length} lowercase hex characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{label} must be lowercase hexadecimal") from exc
    return value


def _is_reparse_point(path: Path) -> bool:
    stat_result = path.lstat()
    attributes = int(getattr(stat_result, "st_file_attributes", 0))
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _same_windows_path(left: PureWindowsPath, right: PureWindowsPath) -> bool:
    return str(left).casefold() == str(right).casefold()


@dataclass(frozen=True)
class AgentPackageGuestLayout:
    """Fixed managed guest destinations for one package-transfer attempt."""

    runtime_root: str
    agent_root: str
    final_package_root: str
    transfer_id: str

    @classmethod
    def from_service_config(
        cls,
        service: AgentServiceConfig,
        *,
        transfer_id: str | None = None,
    ) -> "AgentPackageGuestLayout":
        service.validate()
        return cls(
            runtime_root=service.runtime_path,
            agent_root=service.agent_root_path,
            final_package_root=service.package_path,
            transfer_id=transfer_id or uuid.uuid4().hex,
        )

    def validate(self) -> None:
        _validate_lower_hex(
            self.transfer_id,
            length=_TRANSFER_ID_HEX_LENGTH,
            label="Agent package transfer_id",
        )
        runtime = PureWindowsPath(self.runtime_root)
        agent = PureWindowsPath(self.agent_root)
        package = PureWindowsPath(self.final_package_root)
        for label, path in (
            ("runtime_root", runtime),
            ("agent_root", agent),
            ("final_package_root", package),
        ):
            if not path.is_absolute():
                raise ValueError(f"{label} must be an absolute Windows path")
        if not _same_windows_path(agent.parent, runtime):
            raise ValueError("Agent root must be a direct child of managed runtime root")
        if not _same_windows_path(package.parent, agent):
            raise ValueError("final package root must be a direct child of Agent root")
        if package.name.casefold() != "package":
            raise ValueError("final package root must use the managed package directory")

    @property
    def staging_base(self) -> str:
        self.validate()
        return str(PureWindowsPath(self.runtime_root) / "Staging" / "AgentPackage")

    @property
    def transfer_root(self) -> str:
        return str(PureWindowsPath(self.staging_base) / self.transfer_id)

    @property
    def staging_package_root(self) -> str:
        return str(PureWindowsPath(self.transfer_root) / "package")

    @property
    def staging_manifest_path(self) -> str:
        return str(PureWindowsPath(self.transfer_root) / _MANIFEST_FILENAME)

    @property
    def ownership_marker_path(self) -> str:
        return str(PureWindowsPath(self.transfer_root) / _STAGING_MARKER_NAME)

    @property
    def final_manifest_path(self) -> str:
        return str(PureWindowsPath(self.agent_root) / _MANIFEST_FILENAME)


@dataclass(frozen=True)
class AgentPackageTransferPlan:
    """Host-attested package + exact managed guest placement for one transfer."""

    source_root: Path
    manifest_source: Path
    manifest: AgentPackageManifest
    layout: AgentPackageGuestLayout
    ownership_token: str = field(repr=False)

    @classmethod
    def create(
        cls,
        source_root: Path,
        manifest_source: Path,
        manifest: AgentPackageManifest,
        *,
        service: AgentServiceConfig | None = None,
        transfer_id: str | None = None,
        ownership_token: str | None = None,
    ) -> "AgentPackageTransferPlan":
        managed_service = service or AgentServiceConfig()
        plan = cls(
            source_root=source_root,
            manifest_source=manifest_source,
            manifest=manifest,
            layout=AgentPackageGuestLayout.from_service_config(
                managed_service,
                transfer_id=transfer_id,
            ),
            ownership_token=ownership_token or secrets.token_hex(24),
        )
        plan.validate()
        return plan

    def validate(self) -> None:
        self.layout.validate()
        _validate_lower_hex(
            self.ownership_token,
            length=_OWNERSHIP_TOKEN_HEX_LENGTH,
            label="Agent package transfer ownership token",
        )
        self.manifest.validate()

        # Important: verify before resolving the root so a root symlink/reparse
        # point cannot be canonicalized away before the package trust gate.
        verify_agent_package(self.source_root, self.manifest)

        if not self.manifest_source.is_file():
            raise FileNotFoundError(self.manifest_source)
        if self.manifest_source.is_symlink() or _is_reparse_point(self.manifest_source):
            raise ValueError("Agent package manifest source must not be a link or reparse point")
        published = load_agent_package_manifest(self.manifest_source)
        if published != self.manifest:
            raise ValueError("Agent package manifest source differs from expected manifest")

        source_root = self.source_root.resolve(strict=True)
        manifest_path = self.manifest_source.resolve(strict=True)
        try:
            manifest_path.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise ValueError("Agent package manifest must remain outside the exact package tree")

    @property
    def manifest_sha256(self) -> str:
        self.validate()
        return sha256_file(self.manifest_source).lower()

    @property
    def manifest_size(self) -> int:
        self.validate()
        return self.manifest_source.stat().st_size


def _copy_entries_payload(plan: AgentPackageTransferPlan) -> str:
    plan.validate()
    payload = [
        [item.path, item.size, item.sha256.lower()]
        for item in plan.manifest.files
    ]
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def build_prepare_agent_package_staging_script(plan: AgentPackageTransferPlan) -> str:
    """Create a unique, ownership-marked guest staging root without deleting anything."""
    plan.validate()
    runtime_root = ps_literal(plan.layout.runtime_root)
    staging_base = ps_literal(plan.layout.staging_base)
    transfer_root = ps_literal(plan.layout.transfer_root)
    marker_path = ps_literal(plan.layout.ownership_marker_path)
    ownership_token = ps_literal(plan.ownership_token)

    return f"""
$ErrorActionPreference = 'Stop'
$runtimeRoot = {runtime_root}
$stagingBase = {staging_base}
$transferRoot = {transfer_root}
$markerPath = {marker_path}
$ownershipToken = {ownership_token}

function Assert-HmsManagedDirectory([string]$Path) {{
  if (-not (Test-Path -LiteralPath $Path)) {{
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  }}
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not $item.PSIsContainer) {{ throw "HMS managed staging path is not a directory: $Path" }}
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    throw "HMS managed staging path must not be a reparse point: $Path"
  }}
}}

Assert-HmsManagedDirectory $runtimeRoot
$stagingParent = Split-Path -Parent $stagingBase
Assert-HmsManagedDirectory $stagingParent
Assert-HmsManagedDirectory $stagingBase
if (Test-Path -LiteralPath $transferRoot) {{
  throw 'HMS Agent package transfer root already exists'
}}
[System.IO.Directory]::CreateDirectory($transferRoot) | Out-Null
$transferItem = Get-Item -LiteralPath $transferRoot -Force -ErrorAction Stop
if (($transferItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMS Agent package transfer root became a reparse point'
}}
[System.IO.File]::WriteAllText(
  $markerPath,
  $ownershipToken,
  [System.Text.UTF8Encoding]::new($false)
)
[pscustomobject]@{{
  staging_ready = $true
  transfer_root = $transferRoot
  package_root = {ps_literal(plan.layout.staging_package_root)}
  manifest_path = {ps_literal(plan.layout.staging_manifest_path)}
}}
""".strip()


def build_copy_agent_package_to_staging_script(
    vm_name: str,
    plan: AgentPackageTransferPlan,
) -> str:
    """Build one bounded Guest Service Interface copy window for the full package."""
    if not vm_name.strip():
        raise ValueError("VM name is required")
    plan.validate()

    source_root = plan.source_root.resolve(strict=True)
    manifest_source = plan.manifest_source.resolve(strict=True)
    entries_payload = _copy_entries_payload(plan)
    script = f"""
$ErrorActionPreference = 'Stop'
$vmName = {ps_literal(vm_name)}
$sourceRoot = {ps_literal(source_root)}
$stagingRoot = {ps_literal(plan.layout.staging_package_root)}
$manifestSource = {ps_literal(manifest_source)}
$manifestDestination = {ps_literal(plan.layout.staging_manifest_path)}
$expectedManifestHash = {ps_literal(plan.manifest_sha256)}
$expectedManifestSize = [int64]{plan.manifest_size}
$entriesPayload = {ps_literal(entries_payload)}
$integrationName = 'Guest Service Interface'

{POWERSHELL_SHA256_FUNCTION}

$entriesJson = [System.Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String($entriesPayload)
)
$entries = @($entriesJson | ConvertFrom-Json -ErrorAction Stop)
if ($entries.Count -ne {plan.manifest.file_count}) {{
  throw 'HMS Agent host copy plan file count mismatch'
}}
if (-not (Test-Path -LiteralPath $manifestSource -PathType Leaf)) {{
  throw 'HMS Agent manifest source disappeared before copy'
}}
$manifestItem = Get-Item -LiteralPath $manifestSource -Force -ErrorAction Stop
if (($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMS Agent manifest source became a reparse point'
}}
if ([int64]$manifestItem.Length -ne $expectedManifestSize) {{
  throw 'HMS Agent manifest source size changed before copy'
}}
if ((Get-HmsSha256 $manifestSource) -ne $expectedManifestHash) {{
  throw 'HMS Agent manifest source hash changed before copy'
}}

$service = Get-VMIntegrationService -VMName $vmName -Name $integrationName -ErrorAction Stop
$wasEnabled = [bool]$service.Enabled
$enabledTemporarily = $false
[int]$copiedFiles = 0
try {{
  if (-not $wasEnabled) {{
    Enable-VMIntegrationService -VMName $vmName -Name $integrationName -ErrorAction Stop | Out-Null
    $enabledTemporarily = $true
  }}
  foreach ($entry in $entries) {{
    $relative = [string]$entry[0]
    $expectedSize = [int64]$entry[1]
    $expectedHash = ([string]$entry[2]).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains('\\') -or $relative.StartsWith('/') -or $relative.Contains('../') -or $relative.Contains('/../') -or $relative.EndsWith('/..')) {{
      throw 'HMS Agent host copy plan contains an unsafe relative path'
    }}
    $windowsRelative = $relative.Replace('/', '\\')
    $source = [System.IO.Path]::Combine($sourceRoot, $windowsRelative)
    $destination = [System.IO.Path]::Combine($stagingRoot, $windowsRelative)
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {{
      throw 'HMS Agent package source file disappeared before copy'
    }}
    $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if (($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
      throw 'HMS Agent package source file became a reparse point'
    }}
    if ([int64]$sourceItem.Length -ne $expectedSize) {{
      throw 'HMS Agent package source file size changed before copy'
    }}
    if ((Get-HmsSha256 $source) -ne $expectedHash) {{
      throw 'HMS Agent package source file hash changed before copy'
    }}
    Copy-VMFile -Name $vmName -SourcePath $source -DestinationPath $destination -FileSource Host -CreateFullPath -ErrorAction Stop | Out-Null
    $copiedFiles += 1
  }}
  Copy-VMFile -Name $vmName -SourcePath $manifestSource -DestinationPath $manifestDestination -FileSource Host -CreateFullPath -ErrorAction Stop | Out-Null
  [pscustomobject]@{{
    copied = $true
    copied_files = $copiedFiles
    manifest_copied = $true
    enabled_temporarily = $enabledTemporarily
    staging_root = $stagingRoot
  }}
}} finally {{
  if ($enabledTemporarily) {{
    Disable-VMIntegrationService -VMName $vmName -Name $integrationName -ErrorAction SilentlyContinue | Out-Null
  }}
}}
""".strip()
    if len(script.encode("utf-8")) > _MAX_HOST_COPY_SCRIPT_BYTES:
        raise ValueError(
            "Agent package copy plan exceeds bounded host PowerShell command size; chunked transfer is required"
        )
    return script


def build_publish_agent_package_script(plan: AgentPackageTransferPlan) -> str:
    """Verify staged bytes, publish only into an absent/exact final root, then reverify."""
    plan.validate()
    transfer_root = ps_literal(plan.layout.transfer_root)
    staging_package = ps_literal(plan.layout.staging_package_root)
    staging_manifest = ps_literal(plan.layout.staging_manifest_path)
    marker_path = ps_literal(plan.layout.ownership_marker_path)
    ownership_token = ps_literal(plan.ownership_token)
    agent_root = ps_literal(plan.layout.agent_root)
    final_package = ps_literal(plan.layout.final_package_root)
    final_manifest = ps_literal(plan.layout.final_manifest_path)
    expected_manifest_hash = ps_literal(plan.manifest_sha256)

    return f"""
$ErrorActionPreference = 'Stop'
$transferRoot = {transfer_root}
$stagingPackage = {staging_package}
$stagingManifest = {staging_manifest}
$markerPath = {marker_path}
$ownershipToken = {ownership_token}
$agentRoot = {agent_root}
$finalPackage = {final_package}
$finalManifest = {final_manifest}
$expectedManifestHash = {expected_manifest_hash}
$expectedManifestSize = [int64]{plan.manifest_size}

{POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION}

if (-not (Test-Path -LiteralPath $transferRoot -PathType Container)) {{
  throw 'HMS Agent package transfer root is missing'
}}
$transferItem = Get-Item -LiteralPath $transferRoot -Force -ErrorAction Stop
if (($transferItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMS Agent package transfer root must not be a reparse point'
}}
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {{
  throw 'HMS Agent package transfer ownership marker is missing'
}}
$markerItem = Get-Item -LiteralPath $markerPath -Force -ErrorAction Stop
if (($markerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMS Agent package transfer ownership marker must not be a reparse point'
}}
if ([System.IO.File]::ReadAllText($markerPath) -cne $ownershipToken) {{
  throw 'HMS Agent package transfer ownership marker does not match'
}}
if (-not (Test-Path -LiteralPath $stagingManifest -PathType Leaf)) {{
  throw 'HMS Agent staged manifest is missing'
}}
$manifestItem = Get-Item -LiteralPath $stagingManifest -Force -ErrorAction Stop
if (($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMS Agent staged manifest must not be a reparse point'
}}
if ([int64]$manifestItem.Length -ne $expectedManifestSize) {{
  throw 'HMS Agent staged manifest size mismatch'
}}
if ((Get-HmsSha256 $stagingManifest) -ne $expectedManifestHash) {{
  throw 'HMS Agent staged manifest SHA-256 mismatch'
}}
$manifestPayload = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($stagingManifest))
$stagedProof = Test-HmsAgentPackageTree $stagingPackage $manifestPayload

if (-not (Test-Path -LiteralPath $agentRoot)) {{
  [System.IO.Directory]::CreateDirectory($agentRoot) | Out-Null
}}
$agentItem = Get-Item -LiteralPath $agentRoot -Force -ErrorAction Stop
if (-not $agentItem.PSIsContainer) {{ throw 'HMS Agent root is not a directory' }}
if (($agentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMS Agent root must not be a reparse point'
}}

$finalManifestAlreadyPresent = Test-Path -LiteralPath $finalManifest -PathType Leaf
if ($finalManifestAlreadyPresent) {{
  $finalManifestItem = Get-Item -LiteralPath $finalManifest -Force -ErrorAction Stop
  if (($finalManifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    throw 'Existing HMS Agent manifest must not be a reparse point'
  }}
  if ([int64]$finalManifestItem.Length -ne $expectedManifestSize -or (Get-HmsSha256 $finalManifest) -ne $expectedManifestHash) {{
    throw 'Existing HMS Agent manifest conflicts with staged package'
  }}
}}

$alreadyPublished = Test-Path -LiteralPath $finalPackage -PathType Container
if ($alreadyPublished) {{
  $finalProof = Test-HmsAgentPackageTree $finalPackage $manifestPayload
}} else {{
  if (Test-Path -LiteralPath $finalPackage) {{
    throw 'Existing HMS Agent package target is not a directory'
  }}
  Move-Item -LiteralPath $stagingPackage -Destination $finalPackage -ErrorAction Stop
  $finalProof = Test-HmsAgentPackageTree $finalPackage $manifestPayload
}}

if (-not $finalManifestAlreadyPresent) {{
  Move-Item -LiteralPath $stagingManifest -Destination $finalManifest -ErrorAction Stop
}}
if (-not (Test-Path -LiteralPath $finalManifest -PathType Leaf)) {{
  throw 'HMS Agent final manifest publication failed'
}}
if ((Get-HmsSha256 $finalManifest) -ne $expectedManifestHash) {{
  throw 'HMS Agent final manifest SHA-256 mismatch after publication'
}}
$finalProof = Test-HmsAgentPackageTree $finalPackage $manifestPayload
if ([int]$finalProof.file_count -ne [int]$stagedProof.file_count -or [int64]$finalProof.total_size -ne [int64]$stagedProof.total_size -or [string]$finalProof.entrypoint_sha256 -ne [string]$stagedProof.entrypoint_sha256) {{
  throw 'HMS Agent final package proof differs from staged proof'
}}

# The unique transfer root is destructive-cleanup eligible only because the
# unguessable ownership marker was created before any Copy-VMFile operation.
if (Test-Path -LiteralPath $transferRoot -PathType Container) {{
  if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf) -or [System.IO.File]::ReadAllText($markerPath) -cne $ownershipToken) {{
    throw 'Refusing to clean HMS Agent staging without exact ownership marker'
  }}
  Remove-Item -LiteralPath $transferRoot -Recurse -Force -ErrorAction Stop
}}

[pscustomobject]@{{
  published = $true
  already_published = [bool]$alreadyPublished
  file_count = [int]$finalProof.file_count
  total_size = [int64]$finalProof.total_size
  entrypoint_sha256 = [string]$finalProof.entrypoint_sha256
  final_package_root = $finalPackage
  final_manifest_path = $finalManifest
  staging_removed = [bool](-not (Test-Path -LiteralPath $transferRoot))
}}
""".strip()


def transfer_agent_package_to_guest(
    vm_name: str,
    credential: PowerShellDirectCredential,
    plan: AgentPackageTransferPlan,
    *,
    timeout_seconds: int = 300,
) -> dict[str, object]:
    """Stage, copy, verify, publish and reverify one Agent package transfer."""
    plan.validate()
    prepared = run_vm_powershell_json(
        vm_name,
        credential,
        build_prepare_agent_package_staging_script(plan),
        timeout_seconds=60,
    )
    if not bool(prepared.get("staging_ready", False)):
        raise RuntimeError("HMS Agent package staging preparation failed")

    copied = run_powershell_json(
        build_copy_agent_package_to_staging_script(vm_name, plan),
        timeout_seconds=timeout_seconds,
    )
    if not bool(copied.get("copied", False)):
        raise RuntimeError("HMS Agent package Copy-VMFile transfer failed")
    if int(copied.get("copied_files", 0)) != plan.manifest.file_count:
        raise RuntimeError("HMS Agent package Copy-VMFile count postcondition failed")
    if not bool(copied.get("manifest_copied", False)):
        raise RuntimeError("HMS Agent package manifest copy postcondition failed")

    published = run_vm_powershell_json(
        vm_name,
        credential,
        build_publish_agent_package_script(plan),
        timeout_seconds=timeout_seconds,
    )
    if not bool(published.get("published", False)):
        raise RuntimeError("HMS Agent package guest publication failed")
    if int(published.get("file_count", 0)) != plan.manifest.file_count:
        raise RuntimeError("HMS Agent final package file-count postcondition failed")
    if int(published.get("total_size", 0)) != plan.manifest.total_size:
        raise RuntimeError("HMS Agent final package size postcondition failed")
    if str(published.get("entrypoint_sha256", "")).lower() != plan.manifest.sha256.lower():
        raise RuntimeError("HMS Agent final package entrypoint postcondition failed")
    if not bool(published.get("staging_removed", False)):
        raise RuntimeError("HMS Agent package staging cleanup postcondition failed")

    return {
        "staging_prepared": True,
        "copied_files": plan.manifest.file_count,
        "manifest_copied": True,
        "published": True,
        "already_published": bool(published.get("already_published", False)),
        "file_count": plan.manifest.file_count,
        "total_size": plan.manifest.total_size,
        "entrypoint_sha256": plan.manifest.sha256.lower(),
        "final_package_root": plan.layout.final_package_root,
        "final_manifest_path": plan.layout.final_manifest_path,
        "staging_removed": True,
    }
