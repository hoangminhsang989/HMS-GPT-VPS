from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PureWindowsPath
import secrets
import shutil

from .bridge_package import (
    MAX_BRIDGE_MANIFEST_BYTES,
    BridgePackageManifest,
    require_bridge_windows_amd64_pe,
    verify_bridge_package,
)
from .bridge_service_provisioning_identity import (
    prove_hms_bridge_provisioning_identity,
)
from .qualification_file_authority import (
    lexical_absolute,
    path_chain_has_redirect,
    read_file_pinned,
)
from .powershell import ps_literal, run_powershell_json


DEFAULT_BRIDGE_HOST_ROOT = Path(r"C:\ProgramData\HMS-GPT-VPS\Bridge")
DEFAULT_BRIDGE_PACKAGE_ROOT = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\package"
)
DEFAULT_BRIDGE_PACKAGE_MANIFEST_PATH = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\hms-bridge.manifest.json"
)
DEFAULT_BRIDGE_BINARY_PATH = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\package\hms-bridge.exe"
)
_STAGE_MARKER_NAME = ".hms-bridge-package-stage-owned"
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_STAGE_IDENTITY_KEYS = frozenset(
    {
        "elevated_administrator",
        "process_sid",
        "identity_name",
        "service_present",
    }
)
_ACL_KEYS = frozenset(
    {
        "ready",
        "changed",
        "host_root",
        "package_root",
        "manifest_path",
        "manifest_sha256",
        "entrypoint_sha256",
        "package_file_count",
        "package_directory_count",
        "service_sid",
        "service_acl_enabled",
        "all_acl_exact",
        "reparse_point_found",
    }
)


class BridgePackageDeploymentError(RuntimeError):
    pass


@dataclass(frozen=True)
class BridgePackageDeploymentEvidence:
    ready: bool
    created: bool
    package_root: str
    manifest_path: str
    binary_path: str
    manifest_sha256: str
    binary_sha256: str
    file_count: int
    total_size: int
    service_acl_finalized: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "ready": self.ready,
            "created": self.created,
            "package_root": self.package_root,
            "manifest_path": self.manifest_path,
            "binary_path": self.binary_path,
            "manifest_sha256": self.manifest_sha256,
            "binary_sha256": self.binary_sha256,
            "file_count": self.file_count,
            "total_size": self.total_size,
            "service_acl_finalized": self.service_acl_finalized,
        }


def canonical_bridge_package_manifest_bytes(
    manifest: BridgePackageManifest,
) -> bytes:
    if not isinstance(manifest, BridgePackageManifest):
        raise TypeError("manifest must be a BridgePackageManifest")
    manifest.validate()
    return (manifest.to_json() + "\n").encode("utf-8")


def bridge_package_manifest_sha256(
    manifest: BridgePackageManifest,
) -> str:
    return hashlib.sha256(
        canonical_bridge_package_manifest_bytes(manifest)
    ).hexdigest()


def _fixed_windows_path(path: Path, expected: Path, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} must be pathlib.Path")
    observed_text = str(PureWindowsPath(str(path)))
    expected_text = str(PureWindowsPath(str(expected)))
    if observed_text.casefold() != expected_text.casefold():
        raise BridgePackageDeploymentError(
            f"{label} differs from fixed ProgramData authority"
        )
    return path


def build_bridge_package_staging_identity_script() -> str:
    return r"""
$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {
  throw 'Bridge package staging process token has no user SID'
}
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$admin = $principal.IsInRole(
  [System.Security.Principal.WindowsBuiltInRole]::Administrator
)
$rows = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='HMSBridge'" -ErrorAction Stop)
[pscustomobject]@{
  elevated_administrator = [bool]$admin
  process_sid = [string]$identity.User.Value
  identity_name = [string]$identity.Name
  service_present = [bool]($rows.Count -ne 0)
}
""".strip()


def prove_bridge_package_staging_admin() -> dict[str, object]:
    """Require elevated admin while HMSBridge does not yet exist."""

    result = run_powershell_json(
        build_bridge_package_staging_identity_script(),
        timeout_seconds=30,
    )
    if frozenset(result) != _STAGE_IDENTITY_KEYS:
        raise BridgePackageDeploymentError(
            "Bridge package staging identity evidence schema is invalid"
        )
    if result.get("elevated_administrator") is not True:
        raise BridgePackageDeploymentError(
            "Bridge package staging requires an elevated Administrator token"
        )
    process_sid = result.get("process_sid")
    if (
        not isinstance(process_sid, str)
        or not process_sid
        or process_sid != process_sid.strip()
        or process_sid.startswith("S-1-5-80-")
    ):
        raise BridgePackageDeploymentError(
            "Bridge package staging process SID is invalid"
        )
    identity_name = result.get("identity_name")
    if not isinstance(identity_name, str) or not identity_name:
        raise BridgePackageDeploymentError(
            "Bridge package staging identity name is invalid"
        )
    if result.get("service_present") is not False:
        raise BridgePackageDeploymentError(
            "HMSBridge SCM service must be absent during initial package staging"
        )
    return dict(result)


def _manifest_bytes_match(path: Path, manifest: BridgePackageManifest) -> None:
    expected = canonical_bridge_package_manifest_bytes(manifest)
    actual = read_file_pinned(
        path,
        max_bytes=MAX_BRIDGE_MANIFEST_BYTES,
        label="HMSBridge package manifest",
    )
    if actual != expected:
        raise BridgePackageDeploymentError(
            "staged HMSBridge package manifest differs from authority"
        )


def _verify_package_at(
    package_root: Path,
    manifest_path: Path,
    manifest: BridgePackageManifest,
) -> None:
    if path_chain_has_redirect(package_root):
        raise BridgePackageDeploymentError(
            "HMSBridge package root traverses a link or reparse point"
        )
    if path_chain_has_redirect(manifest_path):
        raise BridgePackageDeploymentError(
            "HMSBridge package manifest traverses a link or reparse point"
        )
    verify_bridge_package(package_root, manifest)
    require_bridge_windows_amd64_pe(package_root / manifest.entrypoint)
    _manifest_bytes_match(manifest_path, manifest)


def build_bridge_package_acl_script(
    host_root: Path,
    manifest: BridgePackageManifest,
    *,
    expected_service_sid: str | None,
    reconcile: bool,
) -> str:
    """Build exact ACL proof/reconciliation for a staged host package tree."""

    if not isinstance(host_root, Path):
        raise TypeError("host_root must be pathlib.Path")
    manifest.validate()
    package_root = host_root / "package"
    manifest_path = host_root / "hms-bridge.manifest.json"
    binary_path = package_root / manifest.entrypoint
    root = ps_literal(str(PureWindowsPath(str(host_root))))
    package = ps_literal(str(PureWindowsPath(str(package_root))))
    manifest_file = ps_literal(str(PureWindowsPath(str(manifest_path))))
    binary = ps_literal(str(PureWindowsPath(str(binary_path))))
    manifest_sha = ps_literal(bridge_package_manifest_sha256(manifest))
    binary_sha = ps_literal(manifest.sha256.lower())
    expected_files = manifest.file_count
    system_sid = ps_literal(_SYSTEM_SID)
    admin_sid = ps_literal(_ADMINISTRATORS_SID)
    service_sid = ps_literal(expected_service_sid or "")
    service_enabled = "$true" if expected_service_sid is not None else "$false"
    reconcile_literal = "$true" if reconcile else "$false"
    return f"""
$ErrorActionPreference = 'Stop'
$hostRoot = [System.IO.Path]::GetFullPath({root})
$packageRoot = [System.IO.Path]::GetFullPath({package})
$manifestPath = [System.IO.Path]::GetFullPath({manifest_file})
$binaryPath = [System.IO.Path]::GetFullPath({binary})
$expectedManifestSha = {manifest_sha}
$expectedBinarySha = {binary_sha}
$expectedFileCount = [int]{expected_files}
$systemSidText = {system_sid}
$administratorsSidText = {admin_sid}
$expectedServiceSid = {service_sid}
$serviceAclEnabled = {service_enabled}
$reconcile = {reconcile_literal}

function Assert-NoReparseChain([string]$path) {{
  $full = [System.IO.Path]::GetFullPath($path)
  $driveRoot = [System.IO.Path]::GetPathRoot($full)
  $relative = $full.Substring($driveRoot.Length)
  $current = $driveRoot
  foreach ($segment in @($relative.Split([System.IO.Path]::DirectorySeparatorChar, [System.StringSplitOptions]::RemoveEmptyEntries))) {{
    $current = [System.IO.Path]::Combine($current, $segment)
    if (Test-Path -LiteralPath $current) {{
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
        throw 'HMSBridge package authority traverses a reparse point'
      }}
    }}
  }}
}}

function New-Sid([string]$text) {{
  return [System.Security.Principal.SecurityIdentifier]::new($text)
}}

function New-Rule(
  [System.Security.Principal.SecurityIdentifier]$sid,
  [System.Security.AccessControl.FileSystemRights]$rights
) {{
  return [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    $rights,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}}

function New-ExactAcl([bool]$isDirectory, [bool]$serviceRead) {{
  $acl = if ($isDirectory) {{
    [System.Security.AccessControl.DirectorySecurity]::new()
  }} else {{
    [System.Security.AccessControl.FileSecurity]::new()
  }}
  $admins = New-Sid $administratorsSidText
  $system = New-Sid $systemSidText
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($admins)
  $acl.AddAccessRule((New-Rule $system ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-Rule $admins ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  if ($serviceRead) {{
    $service = New-Sid $expectedServiceSid
    $acl.AddAccessRule((New-Rule $service (
      [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
      [System.Security.AccessControl.FileSystemRights]::Synchronize
    )))
  }}
  return $acl
}}

function Test-ExactAcl($acl, [bool]$serviceRead) {{
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne $administratorsSidText -or -not $acl.AreAccessRulesProtected) {{
    return $false
  }}
  $expected = @{{}}
  $expected[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
  $expected[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
  if ($serviceRead) {{
    $expected[$expectedServiceSid] = (
      [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
      [System.Security.AccessControl.FileSystemRights]::Synchronize
    )
  }}
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne $expected.Count) {{ return $false }}
  foreach ($rule in $rules) {{
    if (
      $rule.IsInherited -or
      $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
      $rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or
      $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
    ) {{
      return $false
    }}
    $sid = $rule.IdentityReference.Value
    if (-not $expected.ContainsKey($sid)) {{ return $false }}
    if ([int64]$rule.FileSystemRights -ne [int64]$expected[$sid]) {{ return $false }}
  }}
  return $true
}}

Assert-NoReparseChain $hostRoot
Assert-NoReparseChain $packageRoot
Assert-NoReparseChain $manifestPath
if (-not (Test-Path -LiteralPath $hostRoot -PathType Container)) {{
  throw 'HMSBridge host root is missing'
}}
if (-not (Test-Path -LiteralPath $packageRoot -PathType Container)) {{
  throw 'HMSBridge package root is missing'
}}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {{
  throw 'HMSBridge package manifest is missing'
}}
if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {{
  throw 'HMSBridge package entrypoint is missing'
}}
$items = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force -ErrorAction Stop)
$files = @($items | Where-Object {{ -not $_.PSIsContainer }})
$directories = @($items | Where-Object {{ $_.PSIsContainer }})
$rootFiles = @(Get-ChildItem -LiteralPath $hostRoot -File -Force -ErrorAction Stop)
if ($files.Count -ne $expectedFileCount) {{
  throw 'HMSBridge package file count differs from manifest authority'
}}
$all = @((Get-Item -LiteralPath $hostRoot -Force), (Get-Item -LiteralPath $packageRoot -Force)) + $rootFiles + $items
foreach ($item in $all) {{
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    throw 'HMSBridge package tree contains a reparse point'
  }}
}}
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
$binaryHash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($manifestHash -ne $expectedManifestSha) {{
  throw 'HMSBridge package manifest SHA-256 differs from authority'
}}
if ($binaryHash -ne $expectedBinarySha) {{
  throw 'HMSBridge entrypoint SHA-256 differs from authority'
}}

$changed = $false
$hostServiceRead = $serviceAclEnabled
$packageServiceRead = $serviceAclEnabled

function Reconcile-Item([string]$path, [bool]$isDirectory, [bool]$serviceRead) {{
  $current = Get-Acl -LiteralPath $path -ErrorAction Stop
  if (Test-ExactAcl $current $serviceRead) {{ return $false }}
  if (-not $reconcile) {{ throw 'HMSBridge package ACL differs from exact authority' }}
  Set-Acl -LiteralPath $path -AclObject (New-ExactAcl $isDirectory $serviceRead) -ErrorAction Stop
  $after = Get-Acl -LiteralPath $path -ErrorAction Stop
  if (-not (Test-ExactAcl $after $serviceRead)) {{
    throw 'HMSBridge package ACL did not converge to exact authority'
  }}
  return $true
}}

if (Reconcile-Item $hostRoot $true $hostServiceRead) {{ $changed = $true }}
foreach ($rootFile in $rootFiles) {{
  if (Reconcile-Item $rootFile.FullName $false $false) {{ $changed = $true }}
}}
if (Reconcile-Item $packageRoot $true $packageServiceRead) {{ $changed = $true }}
foreach ($directory in $directories) {{
  if (Reconcile-Item $directory.FullName $true $packageServiceRead) {{ $changed = $true }}
}}
foreach ($file in $files) {{
  if (Reconcile-Item $file.FullName $false $packageServiceRead) {{ $changed = $true }}
}}

Assert-NoReparseChain $hostRoot
Assert-NoReparseChain $packageRoot
$allExact = Test-ExactAcl (Get-Acl -LiteralPath $hostRoot -ErrorAction Stop) $hostServiceRead
foreach ($rootFile in $rootFiles) {{
  $allExact = $allExact -and (Test-ExactAcl (Get-Acl -LiteralPath $rootFile.FullName -ErrorAction Stop) $false)
}}
$allExact = $allExact -and (Test-ExactAcl (Get-Acl -LiteralPath $packageRoot -ErrorAction Stop) $packageServiceRead)
foreach ($directory in $directories) {{
  $allExact = $allExact -and (Test-ExactAcl (Get-Acl -LiteralPath $directory.FullName -ErrorAction Stop) $packageServiceRead)
}}
foreach ($file in $files) {{
  $allExact = $allExact -and (Test-ExactAcl (Get-Acl -LiteralPath $file.FullName -ErrorAction Stop) $packageServiceRead)
}}
if (-not $allExact) {{
  throw 'HMSBridge package ACL final proof failed'
}}

[pscustomobject]@{{
  ready = $true
  changed = [bool]$changed
  host_root = [string]$hostRoot
  package_root = [string]$packageRoot
  manifest_path = [string]$manifestPath
  manifest_sha256 = [string]$manifestHash
  entrypoint_sha256 = [string]$binaryHash
  package_file_count = [int]$files.Count
  package_directory_count = [int]$directories.Count
  service_sid = [string]$expectedServiceSid
  service_acl_enabled = [bool]$serviceAclEnabled
  all_acl_exact = [bool]$allExact
  reparse_point_found = $false
}}
""".strip()


def _validate_acl_evidence(
    result: dict[str, object],
    manifest: BridgePackageManifest,
    *,
    host_root: Path,
    expected_service_sid: str | None,
    require_unchanged: bool,
) -> dict[str, object]:
    if frozenset(result) != _ACL_KEYS:
        raise BridgePackageDeploymentError(
            "HMSBridge package ACL evidence schema is invalid"
        )
    if result.get("ready") is not True or result.get("all_acl_exact") is not True:
        raise BridgePackageDeploymentError(
            "HMSBridge package ACL authority is not ready"
        )
    if result.get("reparse_point_found") is not False:
        raise BridgePackageDeploymentError(
            "HMSBridge package ACL evidence reports a reparse point"
        )
    if not isinstance(result.get("changed"), bool):
        raise BridgePackageDeploymentError(
            "HMSBridge package ACL changed evidence is invalid"
        )
    if require_unchanged and result.get("changed") is not False:
        raise BridgePackageDeploymentError(
            "observer-only HMSBridge package ACL proof reported mutation"
        )
    if result.get("manifest_sha256") != bridge_package_manifest_sha256(manifest):
        raise BridgePackageDeploymentError(
            "HMSBridge package manifest SHA-256 evidence differs"
        )
    if result.get("entrypoint_sha256") != manifest.sha256.lower():
        raise BridgePackageDeploymentError(
            "HMSBridge package entrypoint SHA-256 evidence differs"
        )
    if result.get("package_file_count") != manifest.file_count:
        raise BridgePackageDeploymentError(
            "HMSBridge package file-count evidence differs"
        )
    if result.get("service_acl_enabled") is not (expected_service_sid is not None):
        raise BridgePackageDeploymentError(
            "HMSBridge package service-ACL evidence differs"
        )
    if result.get("service_sid") != (expected_service_sid or ""):
        raise BridgePackageDeploymentError(
            "HMSBridge package service SID evidence differs"
        )
    expected_root = str(PureWindowsPath(str(host_root)))
    if (
        not isinstance(result.get("host_root"), str)
        or str(result["host_root"]).casefold() != expected_root.casefold()
    ):
        raise BridgePackageDeploymentError(
            "HMSBridge host-root ACL evidence path differs"
        )
    return dict(result)


def _run_acl(
    host_root: Path,
    manifest: BridgePackageManifest,
    *,
    expected_service_sid: str | None,
    reconcile: bool,
) -> dict[str, object]:
    return _validate_acl_evidence(
        run_powershell_json(
            build_bridge_package_acl_script(
                host_root,
                manifest,
                expected_service_sid=expected_service_sid,
                reconcile=reconcile,
            ),
            timeout_seconds=180,
        ),
        manifest,
        host_root=host_root,
        expected_service_sid=expected_service_sid,
        require_unchanged=not reconcile,
    )


def _safe_owned_cleanup(root: Path, marker_token: str) -> None:
    marker = root / _STAGE_MARKER_NAME
    if (
        root.exists()
        and not path_chain_has_redirect(root)
        and marker.is_file()
        and marker.read_text(encoding="utf-8") == marker_token
    ):
        shutil.rmtree(root)


def _stage_paths() -> tuple[Path, Path, Path, Path]:
    host_root = lexical_absolute(DEFAULT_BRIDGE_HOST_ROOT)
    package_root = lexical_absolute(DEFAULT_BRIDGE_PACKAGE_ROOT)
    manifest_path = lexical_absolute(DEFAULT_BRIDGE_PACKAGE_MANIFEST_PATH)
    binary_path = lexical_absolute(DEFAULT_BRIDGE_BINARY_PATH)
    _fixed_windows_path(host_root, DEFAULT_BRIDGE_HOST_ROOT, "host_root")
    _fixed_windows_path(package_root, DEFAULT_BRIDGE_PACKAGE_ROOT, "package_root")
    _fixed_windows_path(
        manifest_path,
        DEFAULT_BRIDGE_PACKAGE_MANIFEST_PATH,
        "manifest_path",
    )
    _fixed_windows_path(binary_path, DEFAULT_BRIDGE_BINARY_PATH, "binary_path")
    return host_root, package_root, manifest_path, binary_path


def _evidence(
    manifest: BridgePackageManifest,
    *,
    created: bool,
    service_acl_finalized: bool,
) -> BridgePackageDeploymentEvidence:
    host_root, package_root, manifest_path, binary_path = _stage_paths()
    return BridgePackageDeploymentEvidence(
        ready=True,
        created=created,
        package_root=str(PureWindowsPath(str(package_root))),
        manifest_path=str(PureWindowsPath(str(manifest_path))),
        binary_path=str(PureWindowsPath(str(binary_path))),
        manifest_sha256=bridge_package_manifest_sha256(manifest),
        binary_sha256=manifest.sha256.lower(),
        file_count=manifest.file_count,
        total_size=manifest.total_size,
        service_acl_finalized=service_acl_finalized,
    )


def stage_bridge_package_create_only(
    source_root: Path,
    manifest: BridgePackageManifest,
) -> BridgePackageDeploymentEvidence:
    """Stage an attested Bridge package before the HMSBridge SCM service exists."""

    if not isinstance(source_root, Path):
        raise TypeError("source_root must be pathlib.Path")
    if not isinstance(manifest, BridgePackageManifest):
        raise TypeError("manifest must be a BridgePackageManifest")
    manifest.validate()
    source_root = lexical_absolute(source_root)
    verify_bridge_package(source_root, manifest)
    require_bridge_windows_amd64_pe(source_root / manifest.entrypoint)

    host_root, package_root, manifest_path, _ = _stage_paths()
    if host_root.exists():
        if not package_root.is_dir() or not manifest_path.is_file():
            raise BridgePackageDeploymentError(
                "fixed HMSBridge host root already exists without an exact staged package"
            )
        _verify_package_at(package_root, manifest_path, manifest)
        return _evidence(
            manifest,
            created=False,
            service_acl_finalized=False,
        )

    prove_bridge_package_staging_admin()
    parent = host_root.parent
    if path_chain_has_redirect(parent):
        raise BridgePackageDeploymentError(
            "HMSBridge package parent traverses a link or reparse point"
        )
    parent.mkdir(parents=True, exist_ok=True)
    if path_chain_has_redirect(parent):
        raise BridgePackageDeploymentError(
            "HMSBridge package parent became redirected"
        )

    marker_token = secrets.token_hex(32)
    temp_root = host_root.with_name(
        host_root.name + ".hms-" + secrets.token_hex(12) + ".tmp"
    )
    temp_package = temp_root / "package"
    temp_manifest = temp_root / "hms-bridge.manifest.json"
    published = False
    try:
        temp_root.mkdir()
        (temp_root / _STAGE_MARKER_NAME).write_text(
            marker_token,
            encoding="utf-8",
        )
        shutil.copytree(source_root, temp_package, symlinks=False)
        manifest_bytes = canonical_bridge_package_manifest_bytes(manifest)
        with temp_manifest.open("xb") as handle:
            handle.write(manifest_bytes)
            handle.flush()
            os.fsync(handle.fileno())

        _verify_package_at(temp_package, temp_manifest, manifest)
        _run_acl(
            temp_root,
            manifest,
            expected_service_sid=None,
            reconcile=True,
        )
        _run_acl(
            temp_root,
            manifest,
            expected_service_sid=None,
            reconcile=False,
        )

        prove_bridge_package_staging_admin()
        if host_root.exists():
            raise BridgePackageDeploymentError(
                "fixed HMSBridge host root appeared during create-only staging"
            )
        os.rename(temp_root, host_root)
        published = True

        _verify_package_at(package_root, manifest_path, manifest)
        _run_acl(
            host_root,
            manifest,
            expected_service_sid=None,
            reconcile=False,
        )
        (host_root / _STAGE_MARKER_NAME).unlink()
        return _evidence(
            manifest,
            created=True,
            service_acl_finalized=False,
        )
    except BaseException:
        if not published:
            _safe_owned_cleanup(temp_root, marker_token)
        else:
            try:
                prove_bridge_package_staging_admin()
                _safe_owned_cleanup(host_root, marker_token)
            except Exception:
                pass
        raise


def finalize_bridge_package_service_acl(
    manifest: BridgePackageManifest,
) -> BridgePackageDeploymentEvidence:
    """Grant exact read/execute package access only after HMSBridge SCM identity exists."""

    if not isinstance(manifest, BridgePackageManifest):
        raise TypeError("manifest must be a BridgePackageManifest")
    manifest.validate()
    host_root, package_root, manifest_path, _ = _stage_paths()
    _verify_package_at(package_root, manifest_path, manifest)
    pre = prove_hms_bridge_provisioning_identity()
    service_sid = pre.get("service_sid")
    if not isinstance(service_sid, str):
        raise BridgePackageDeploymentError(
            "HMSBridge service SID proof is invalid during package ACL finalization"
        )

    _run_acl(
        host_root,
        manifest,
        expected_service_sid=service_sid,
        reconcile=True,
    )
    _verify_package_at(package_root, manifest_path, manifest)
    _run_acl(
        host_root,
        manifest,
        expected_service_sid=service_sid,
        reconcile=False,
    )
    post = prove_hms_bridge_provisioning_identity()
    if post.get("service_sid") != service_sid:
        raise BridgePackageDeploymentError(
            "HMSBridge service SID changed across package ACL finalization"
        )
    return _evidence(
        manifest,
        created=False,
        service_acl_finalized=True,
    )
