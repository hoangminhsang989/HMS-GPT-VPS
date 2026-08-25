from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .powershell import ps_literal, run_powershell_json
from .qualification_file_authority import lexical_absolute, path_chain_has_redirect


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_FORBIDDEN_READER_SIDS = frozenset(
    {
        "S-1-1-0",       # Everyone
        "S-1-5-7",       # Anonymous
        "S-1-5-11",      # Authenticated Users
        "S-1-5-32-545",  # Users
        "S-1-5-32-546",  # Guests
        "S-1-5-32-547",  # Power Users
    }
)
_SID_RE = re.compile(r"^S-1-(?:\d+)(?:-\d+)+$")
_HEX_SHA256_LENGTH = 64
_RESULT_KEYS = frozenset(
    {
        "ready",
        "changed",
        "storage_root",
        "private_key_path",
        "private_key_sha256",
        "storage_owner_sid",
        "private_key_owner_sid",
        "bridge_reader_sid",
        "storage_acl_exact",
        "private_key_acl_exact",
        "storage_entry_count",
        "private_key_reparse_point",
        "storage_reparse_point",
    }
)


class AgentBridgeTlsStorageError(RuntimeError):
    pass


def _require_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _HEX_SHA256_LENGTH
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise AgentBridgeTlsStorageError(
            f"{name} must be canonical lowercase SHA-256 hex"
        )
    return value


def _require_service_sid(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not _SID_RE.fullmatch(value)
    ):
        raise AgentBridgeTlsStorageError(f"{name} is not a canonical SID")
    if value in _FORBIDDEN_READER_SIDS:
        raise AgentBridgeTlsStorageError(
            f"{name} must not be a broad Windows principal"
        )
    # HMS Bridge is intended to run under a dedicated Windows service SID.
    # S-1-5-80 is the NT SERVICE SID authority.
    if not value.startswith("S-1-5-80-"):
        raise AgentBridgeTlsStorageError(
            f"{name} must be a dedicated NT SERVICE SID"
        )
    return value


@dataclass(frozen=True)
class AgentBridgePrivateKeyStorageConfig:
    storage_root: Path
    private_key_path: Path
    private_key_file_sha256: str
    bridge_reader_sid: str

    def validate(self) -> None:
        if not isinstance(self.storage_root, Path):
            raise TypeError("storage_root must be a pathlib.Path")
        if not isinstance(self.private_key_path, Path):
            raise TypeError("private_key_path must be a pathlib.Path")
        root = lexical_absolute(self.storage_root)
        key = lexical_absolute(self.private_key_path)
        if path_chain_has_redirect(root):
            raise AgentBridgeTlsStorageError(
                "Agent Bridge TLS storage root traverses a link or reparse point"
            )
        if path_chain_has_redirect(key):
            raise AgentBridgeTlsStorageError(
                "Agent Bridge private key path traverses a link or reparse point"
            )
        if key.parent != root:
            raise AgentBridgeTlsStorageError(
                "Agent Bridge private key must be a direct child of the dedicated TLS storage root"
            )
        if key.name in {"", ".", ".."}:
            raise AgentBridgeTlsStorageError(
                "Agent Bridge private key filename is invalid"
            )
        _require_sha256(
            self.private_key_file_sha256,
            "private_key_file_sha256",
        )
        _require_service_sid(self.bridge_reader_sid, "bridge_reader_sid")


def build_agent_bridge_private_key_storage_script(
    config: AgentBridgePrivateKeyStorageConfig,
) -> str:
    config.validate()
    root = ps_literal(str(lexical_absolute(config.storage_root)))
    key = ps_literal(str(lexical_absolute(config.private_key_path)))
    reader_sid = ps_literal(config.bridge_reader_sid)
    expected_sha = ps_literal(config.private_key_file_sha256)
    system_sid = ps_literal(_SYSTEM_SID)
    administrators_sid = ps_literal(_ADMINISTRATORS_SID)

    return f"""
$ErrorActionPreference = 'Stop'
$storageRoot = [System.IO.Path]::GetFullPath({root})
$privateKeyPath = [System.IO.Path]::GetFullPath({key})
$readerSidText = {reader_sid}
$expectedSha256 = {expected_sha}
$systemSidText = {system_sid}
$administratorsSidText = {administrators_sid}

function Assert-NoReparseChain([string]$path) {{
  $full = [System.IO.Path]::GetFullPath($path)
  $root = [System.IO.Path]::GetPathRoot($full)
  $relative = $full.Substring($root.Length)
  $current = $root
  foreach ($segment in @($relative.Split([System.IO.Path]::DirectorySeparatorChar, [System.StringSplitOptions]::RemoveEmptyEntries))) {{
    $current = [System.IO.Path]::Combine($current, $segment)
    if (Test-Path -LiteralPath $current) {{
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
        throw "TLS storage authority traverses a reparse point"
      }}
    }}
  }}
}}

function New-Sid([string]$text) {{
  return [System.Security.Principal.SecurityIdentifier]::new($text)
}}

function New-FileRule(
  [System.Security.Principal.SecurityIdentifier]$sid,
  [System.Security.AccessControl.FileSystemRights]$rights
) {{
  return [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    $rights,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}}

function New-DirectoryRule(
  [System.Security.Principal.SecurityIdentifier]$sid,
  [System.Security.AccessControl.FileSystemRights]$rights
) {{
  return [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    $rights,
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}}

function Test-ExactAcl(
  [System.Security.AccessControl.FileSystemSecurity]$acl,
  [hashtable]$expected,
  [string]$ownerSidText,
  [bool]$directory
) {{
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne $ownerSidText) {{ return $false }}
  if (-not $acl.AreAccessRulesProtected) {{ return $false }}
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne $expected.Count) {{ return $false }}
  foreach ($rule in $rules) {{
    if ($rule.IsInherited) {{ return $false }}
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {{
      return $false
    }}
    $sid = $rule.IdentityReference.Value
    if (-not $expected.ContainsKey($sid)) {{ return $false }}
    $spec = $expected[$sid]
    if ([int64]$rule.FileSystemRights -ne [int64]$spec.rights) {{ return $false }}
    if ($directory) {{
      $wantedInheritance =
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
      if ($rule.InheritanceFlags -ne $wantedInheritance) {{ return $false }}
      if ($rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {{
        return $false
      }}
    }} else {{
      if ($rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None) {{
        return $false
      }}
      if ($rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {{
        return $false
      }}
    }}
  }}
  return $true
}}

Assert-NoReparseChain $storageRoot
Assert-NoReparseChain $privateKeyPath
$rootItem = Get-Item -LiteralPath $storageRoot -Force -ErrorAction Stop
if (-not $rootItem.PSIsContainer) {{ throw 'TLS storage root is not a directory' }}
$keyItem = Get-Item -LiteralPath $privateKeyPath -Force -ErrorAction Stop
if ($keyItem.PSIsContainer) {{ throw 'TLS private-key authority is not a file' }}
if ([System.IO.Path]::GetDirectoryName($privateKeyPath) -ine $storageRoot) {{
  throw 'TLS private key is not a direct storage-root child'
}}
$entries = @(Get-ChildItem -LiteralPath $storageRoot -Force -ErrorAction Stop)
if ($entries.Count -ne 1 -or $entries[0].FullName -ine $privateKeyPath) {{
  throw 'Dedicated TLS storage root contains unexpected entries'
}}
$beforeSha = (Get-FileHash -LiteralPath $privateKeyPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($beforeSha -ne $expectedSha256) {{
  throw 'TLS private-key SHA-256 differs from deployment authority before ACL reconciliation'
}}

$systemSid = New-Sid $systemSidText
$administratorsSid = New-Sid $administratorsSidText
$readerSid = New-Sid $readerSidText
$expectedDirectory = @{{}}
$expectedDirectory[$systemSidText] = @{{ rights = [System.Security.AccessControl.FileSystemRights]::FullControl }}
$expectedDirectory[$administratorsSidText] = @{{ rights = [System.Security.AccessControl.FileSystemRights]::FullControl }}
$expectedDirectory[$readerSidText] = @{{ rights = (
  [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
  [System.Security.AccessControl.FileSystemRights]::Synchronize
) }}
$expectedFile = @{{}}
$expectedFile[$systemSidText] = @{{ rights = [System.Security.AccessControl.FileSystemRights]::FullControl }}
$expectedFile[$administratorsSidText] = @{{ rights = [System.Security.AccessControl.FileSystemRights]::FullControl }}
$expectedFile[$readerSidText] = @{{ rights = (
  [System.Security.AccessControl.FileSystemRights]::Read -bor
  [System.Security.AccessControl.FileSystemRights]::Synchronize
) }}

$changed = $false
$rootAcl = Get-Acl -LiteralPath $storageRoot -ErrorAction Stop
if (-not (Test-ExactAcl $rootAcl $expectedDirectory $administratorsSidText $true)) {{
  $newRootAcl = [System.Security.AccessControl.DirectorySecurity]::new()
  $newRootAcl.SetAccessRuleProtection($true, $false)
  $newRootAcl.SetOwner($administratorsSid)
  $newRootAcl.AddAccessRule((New-DirectoryRule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newRootAcl.AddAccessRule((New-DirectoryRule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newRootAcl.AddAccessRule((New-DirectoryRule $readerSid ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)))
  Set-Acl -LiteralPath $storageRoot -AclObject $newRootAcl -ErrorAction Stop
  $changed = $true
}}

$keyAcl = Get-Acl -LiteralPath $privateKeyPath -ErrorAction Stop
if (-not (Test-ExactAcl $keyAcl $expectedFile $administratorsSidText $false)) {{
  $newKeyAcl = [System.Security.AccessControl.FileSecurity]::new()
  $newKeyAcl.SetAccessRuleProtection($true, $false)
  $newKeyAcl.SetOwner($administratorsSid)
  $newKeyAcl.AddAccessRule((New-FileRule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newKeyAcl.AddAccessRule((New-FileRule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newKeyAcl.AddAccessRule((New-FileRule $readerSid ([System.Security.AccessControl.FileSystemRights]::Read)))
  Set-Acl -LiteralPath $privateKeyPath -AclObject $newKeyAcl -ErrorAction Stop
  $changed = $true
}}

Assert-NoReparseChain $storageRoot
Assert-NoReparseChain $privateKeyPath
$rootItem = Get-Item -LiteralPath $storageRoot -Force -ErrorAction Stop
$keyItem = Get-Item -LiteralPath $privateKeyPath -Force -ErrorAction Stop
$entries = @(Get-ChildItem -LiteralPath $storageRoot -Force -ErrorAction Stop)
if ($entries.Count -ne 1 -or $entries[0].FullName -ine $privateKeyPath) {{
  throw 'Dedicated TLS storage root changed during ACL reconciliation'
}}
$afterSha = (Get-FileHash -LiteralPath $privateKeyPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($afterSha -ne $expectedSha256 -or $afterSha -ne $beforeSha) {{
  throw 'TLS private-key content changed during ACL reconciliation'
}}
$rootAcl = Get-Acl -LiteralPath $storageRoot -ErrorAction Stop
$keyAcl = Get-Acl -LiteralPath $privateKeyPath -ErrorAction Stop
$rootExact = Test-ExactAcl $rootAcl $expectedDirectory $administratorsSidText $true
$keyExact = Test-ExactAcl $keyAcl $expectedFile $administratorsSidText $false
if (-not $rootExact -or -not $keyExact) {{
  throw 'TLS storage ACL did not converge to exact authority'
}}

[pscustomobject]@{{
  ready = $true
  changed = [bool]$changed
  storage_root = [string]$storageRoot
  private_key_path = [string]$privateKeyPath
  private_key_sha256 = [string]$afterSha
  storage_owner_sid = [string]$rootAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  private_key_owner_sid = [string]$keyAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  bridge_reader_sid = [string]$readerSidText
  storage_acl_exact = [bool]$rootExact
  private_key_acl_exact = [bool]$keyExact
  storage_entry_count = [int]$entries.Count
  private_key_reparse_point = [bool](($keyItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
  storage_reparse_point = [bool](($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}}
""".strip()


def _validate_result(
    result: dict[str, object],
    config: AgentBridgePrivateKeyStorageConfig,
) -> None:
    if frozenset(result) != _RESULT_KEYS:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge TLS storage evidence schema is invalid"
        )
    if result.get("ready") is not True:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge TLS storage is not ready"
        )
    if not isinstance(result.get("changed"), bool):
        raise AgentBridgeTlsStorageError(
            "Agent Bridge TLS storage changed evidence is invalid"
        )
    if result.get("storage_acl_exact") is not True:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge TLS storage ACL is not exact"
        )
    if result.get("private_key_acl_exact") is not True:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge private-key ACL is not exact"
        )
    if result.get("private_key_reparse_point") is not False:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge private key is a reparse point"
        )
    if result.get("storage_reparse_point") is not False:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge TLS storage root is a reparse point"
        )
    if result.get("storage_entry_count") != 1:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge TLS storage root is not dedicated to one private key"
        )
    expected_root = str(lexical_absolute(config.storage_root))
    expected_key = str(lexical_absolute(config.private_key_path))
    expected = {
        "storage_root": expected_root,
        "private_key_path": expected_key,
        "private_key_sha256": config.private_key_file_sha256,
        "storage_owner_sid": _ADMINISTRATORS_SID,
        "private_key_owner_sid": _ADMINISTRATORS_SID,
        "bridge_reader_sid": config.bridge_reader_sid,
    }
    for key, wanted in expected.items():
        observed = result.get(key)
        if not isinstance(observed, str) or observed.casefold() != wanted.casefold():
            raise AgentBridgeTlsStorageError(
                f"Agent Bridge TLS storage evidence differs from authority: {key}"
            )


def ensure_agent_bridge_private_key_storage(
    config: AgentBridgePrivateKeyStorageConfig,
) -> dict[str, object]:
    if not isinstance(config, AgentBridgePrivateKeyStorageConfig):
        raise TypeError("config must be an AgentBridgePrivateKeyStorageConfig")
    config.validate()
    result = run_powershell_json(
        build_agent_bridge_private_key_storage_script(config),
        timeout_seconds=60,
    )
    _validate_result(result, config)
    return dict(result)


_PROCESS_IDENTITY_KEYS = frozenset(
    {"process_sid", "identity_name", "dedicated_service_sid"}
)


def prove_agent_bridge_process_reader_identity(
    config: AgentBridgePrivateKeyStorageConfig,
) -> dict[str, object]:
    """Prove the host process is running under the configured Bridge service SID.

    ``run_powershell_json`` inherits the caller token, so the child identity is a
    direct process-token proof for the Python Bridge runtime. Production startup
    uses this before touching TLS material; privileged provisioning may call
    ``ensure_agent_bridge_private_key_storage`` separately.
    """

    if not isinstance(config, AgentBridgePrivateKeyStorageConfig):
        raise TypeError("config must be an AgentBridgePrivateKeyStorageConfig")
    config.validate()
    script = r"""
$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {
  throw 'Current Windows process token has no user SID'
}
$sid = [string]$identity.User.Value
[pscustomobject]@{
  process_sid = $sid
  identity_name = [string]$identity.Name
  dedicated_service_sid = [bool]$sid.StartsWith('S-1-5-80-')
}
""".strip()
    result = run_powershell_json(script, timeout_seconds=30)
    if frozenset(result) != _PROCESS_IDENTITY_KEYS:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge process-identity evidence schema is invalid"
        )
    if result.get("process_sid") != config.bridge_reader_sid:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge process is not running under the configured service SID"
        )
    if result.get("dedicated_service_sid") is not True:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge process identity is not a dedicated NT SERVICE SID"
        )
    identity_name = result.get("identity_name")
    if not isinstance(identity_name, str) or not identity_name:
        raise AgentBridgeTlsStorageError(
            "Agent Bridge process identity name is invalid"
        )
    return dict(result)
