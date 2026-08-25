from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .bridge_service_identity import require_hms_bridge_service_sid
from .powershell import ps_literal, run_powershell_json
from .qualification_file_authority import lexical_absolute, path_chain_has_redirect


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_PAIRING_KEY_FILENAME = "pairing-exchange-key.service-machine.dpapi"
_CREDENTIALS_DIRNAME = "agent-credentials"
_CREDENTIAL_SUFFIX = ".service-machine.dpapi"
_RESULT_KEYS = frozenset(
    {
        "ready",
        "changed",
        "root",
        "credentials_dir",
        "pairing_key_path",
        "pairing_key_present",
        "credential_file_count",
        "root_acl_exact",
        "credentials_acl_exact",
        "secret_file_acls_exact",
        "unknown_entries_present",
        "reparse_points_present",
    }
)


class BridgeServiceSecretStorageError(RuntimeError):
    pass


@dataclass(frozen=True)
class BridgeServiceSecretStorageConfig:
    root: Path
    bridge_reader_sid: str

    def validate(self) -> None:
        if not isinstance(self.root, Path):
            raise TypeError("root must be a pathlib.Path")
        authority = lexical_absolute(self.root)
        if path_chain_has_redirect(authority):
            raise BridgeServiceSecretStorageError(
                "Bridge service secret root traverses a link or reparse point"
            )
        if authority.name != "service-runtime":
            raise BridgeServiceSecretStorageError(
                "Bridge service secret root must be the fixed service-runtime directory"
            )
        if not authority.parent.exists() or not authority.parent.is_dir():
            raise BridgeServiceSecretStorageError(
                "Bridge service secret parent must already exist"
            )
        require_hms_bridge_service_sid(self.bridge_reader_sid)

    @property
    def authority_root(self) -> Path:
        self.validate()
        return lexical_absolute(self.root)

    @property
    def credentials_dir(self) -> Path:
        return self.authority_root / _CREDENTIALS_DIRNAME

    @property
    def pairing_key_path(self) -> Path:
        return self.authority_root / _PAIRING_KEY_FILENAME


def service_agent_credential_filename(instance_id: str) -> str:
    import hashlib

    if (
        not isinstance(instance_id, str)
        or not instance_id
        or len(instance_id) > 128
        or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for char in instance_id
        )
    ):
        raise BridgeServiceSecretStorageError("instance_id is invalid")
    digest = hashlib.sha256(instance_id.encode("utf-8")).hexdigest()
    return digest + _CREDENTIAL_SUFFIX


def service_agent_credential_path(
    config: BridgeServiceSecretStorageConfig,
    instance_id: str,
) -> Path:
    return config.credentials_dir / service_agent_credential_filename(instance_id)


def build_bridge_service_secret_storage_script(
    config: BridgeServiceSecretStorageConfig,
    *,
    reconcile: bool,
) -> str:
    config.validate()
    root = ps_literal(str(config.authority_root))
    credentials_dir = ps_literal(str(config.credentials_dir))
    pairing_key = ps_literal(str(config.pairing_key_path))
    reader_sid = ps_literal(config.bridge_reader_sid)
    system_sid = ps_literal(_SYSTEM_SID)
    administrators_sid = ps_literal(_ADMINISTRATORS_SID)
    reconcile_literal = "$true" if reconcile else "$false"
    suffix = ps_literal(_CREDENTIAL_SUFFIX)
    return f"""
$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath({root})
$credentialsDir = [System.IO.Path]::GetFullPath({credentials_dir})
$pairingKey = [System.IO.Path]::GetFullPath({pairing_key})
$readerSidText = {reader_sid}
$systemSidText = {system_sid}
$administratorsSidText = {administrators_sid}
$credentialSuffix = {suffix}
$reconcile = {reconcile_literal}
$changed = $false

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
        throw 'Bridge service secret authority traverses a reparse point'
      }}
    }}
  }}
}}

function New-Sid([string]$text) {{
  return [System.Security.Principal.SecurityIdentifier]::new($text)
}}

function New-DirectoryRule($sid, $rights) {{
  return [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    $rights,
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}}

function New-FileRule($sid, $rights) {{
  return [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    $rights,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}}

function Test-ExactAcl($acl, $expected, [bool]$directory) {{
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne $administratorsSidText -or -not $acl.AreAccessRulesProtected) {{ return $false }}
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne $expected.Count) {{ return $false }}
  foreach ($rule in $rules) {{
    if ($rule.IsInherited) {{ return $false }}
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {{ return $false }}
    $sid = $rule.IdentityReference.Value
    if (-not $expected.ContainsKey($sid)) {{ return $false }}
    if ([int64]$rule.FileSystemRights -ne [int64]$expected[$sid]) {{ return $false }}
    if ($directory) {{
      $wanted = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
      if ($rule.InheritanceFlags -ne $wanted -or $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {{ return $false }}
    }} else {{
      if ($rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {{ return $false }}
    }}
  }}
  return $true
}}

$systemSid = New-Sid $systemSidText
$administratorsSid = New-Sid $administratorsSidText
$readerSid = New-Sid $readerSidText
$directoryExpected = @{{}}
$directoryExpected[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$directoryExpected[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$directoryExpected[$readerSidText] = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
$fileExpected = @{{}}
$fileExpected[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$fileExpected[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$fileExpected[$readerSidText] = [System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Synchronize

if (-not (Test-Path -LiteralPath $root)) {{
  if (-not $reconcile) {{ throw 'Bridge service secret root is missing' }}
  New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
  $changed = $true
}}
if (-not (Test-Path -LiteralPath $credentialsDir)) {{
  if (-not $reconcile) {{ throw 'Bridge service credential directory is missing' }}
  New-Item -ItemType Directory -Path $credentialsDir -ErrorAction Stop | Out-Null
  $changed = $true
}}
Assert-NoReparseChain $root
Assert-NoReparseChain $credentialsDir
$rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
$credentialsItem = Get-Item -LiteralPath $credentialsDir -Force -ErrorAction Stop
if (-not $rootItem.PSIsContainer -or -not $credentialsItem.PSIsContainer) {{ throw 'Bridge service secret directory authority is invalid' }}

function Ensure-DirectoryAcl([string]$path) {{
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
  if (Test-ExactAcl $acl $directoryExpected $true) {{ return $false }}
  if (-not $reconcile) {{ throw 'Bridge service secret directory ACL differs from authority' }}
  $newAcl = [System.Security.AccessControl.DirectorySecurity]::new()
  $newAcl.SetAccessRuleProtection($true, $false)
  $newAcl.SetOwner($administratorsSid)
  $newAcl.AddAccessRule((New-DirectoryRule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newAcl.AddAccessRule((New-DirectoryRule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $newAcl.AddAccessRule((New-DirectoryRule $readerSid ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)))
  Set-Acl -LiteralPath $path -AclObject $newAcl -ErrorAction Stop
  if (-not (Test-ExactAcl (Get-Acl -LiteralPath $path -ErrorAction Stop) $directoryExpected $true)) {{ throw 'Bridge service secret directory ACL did not converge' }}
  return $true
}}

if (Ensure-DirectoryAcl $root) {{ $changed = $true }}
if (Ensure-DirectoryAcl $credentialsDir) {{ $changed = $true }}

$rootEntries = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
$unknown = @($rootEntries | Where-Object {{ $_.Name -ne 'agent-credentials' -and $_.Name -ne 'pairing-exchange-key.service-machine.dpapi' }})
if ($unknown.Count -ne 0) {{ throw 'Bridge service secret root contains unknown entries' }}

$credentialFiles = @(Get-ChildItem -LiteralPath $credentialsDir -Force -ErrorAction Stop)
foreach ($entry in $credentialFiles) {{
  if ($entry.PSIsContainer -or $entry.Name -notmatch ('^[0-9a-f]{{64}}' + [regex]::Escape($credentialSuffix) + '$')) {{
    throw 'Bridge service credential directory contains an invalid entry'
  }}
}}

$secretFiles = @()
$pairingPresent = Test-Path -LiteralPath $pairingKey -PathType Leaf
if ($pairingPresent) {{ $secretFiles += Get-Item -LiteralPath $pairingKey -Force -ErrorAction Stop }}
$secretFiles += $credentialFiles
foreach ($file in $secretFiles) {{
  Assert-NoReparseChain $file.FullName
  if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'Bridge service secret file is a reparse point' }}
  $acl = Get-Acl -LiteralPath $file.FullName -ErrorAction Stop
  if (-not (Test-ExactAcl $acl $fileExpected $false)) {{
    if (-not $reconcile) {{ throw 'Bridge service secret file ACL differs from authority' }}
    $newAcl = [System.Security.AccessControl.FileSecurity]::new()
    $newAcl.SetAccessRuleProtection($true, $false)
    $newAcl.SetOwner($administratorsSid)
    $newAcl.AddAccessRule((New-FileRule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
    $newAcl.AddAccessRule((New-FileRule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
    $newAcl.AddAccessRule((New-FileRule $readerSid ([System.Security.AccessControl.FileSystemRights]::Read)))
    Set-Acl -LiteralPath $file.FullName -AclObject $newAcl -ErrorAction Stop
    if (-not (Test-ExactAcl (Get-Acl -LiteralPath $file.FullName -ErrorAction Stop) $fileExpected $false)) {{ throw 'Bridge service secret file ACL did not converge' }}
    $changed = $true
  }}
}}

$rootExact = Test-ExactAcl (Get-Acl -LiteralPath $root -ErrorAction Stop) $directoryExpected $true
$credentialsExact = Test-ExactAcl (Get-Acl -LiteralPath $credentialsDir -ErrorAction Stop) $directoryExpected $true
$filesExact = $true
foreach ($file in $secretFiles) {{
  if (-not (Test-ExactAcl (Get-Acl -LiteralPath $file.FullName -ErrorAction Stop) $fileExpected $false)) {{ $filesExact = $false }}
}}
[pscustomobject]@{{
  ready = [bool]($rootExact -and $credentialsExact -and $filesExact)
  changed = [bool]$changed
  root = [string]$root
  credentials_dir = [string]$credentialsDir
  pairing_key_path = [string]$pairingKey
  pairing_key_present = [bool]$pairingPresent
  credential_file_count = [int]$credentialFiles.Count
  root_acl_exact = [bool]$rootExact
  credentials_acl_exact = [bool]$credentialsExact
  secret_file_acls_exact = [bool]$filesExact
  unknown_entries_present = $false
  reparse_points_present = $false
}}
""".strip()


def _validate_result(
    result: dict[str, object],
    config: BridgeServiceSecretStorageConfig,
    *,
    reconcile: bool,
    require_pairing_key: bool,
) -> dict[str, object]:
    if frozenset(result) != _RESULT_KEYS:
        raise BridgeServiceSecretStorageError(
            "Bridge service secret storage evidence schema is invalid"
        )
    if result.get("ready") is not True:
        raise BridgeServiceSecretStorageError(
            "Bridge service secret storage is not ready"
        )
    if not isinstance(result.get("changed"), bool):
        raise BridgeServiceSecretStorageError("Bridge service secret changed evidence is invalid")
    if not reconcile and result.get("changed") is not False:
        raise BridgeServiceSecretStorageError(
            "Bridge service runtime must not reconcile secret storage"
        )
    expected_paths = {
        "root": str(config.authority_root),
        "credentials_dir": str(config.credentials_dir),
        "pairing_key_path": str(config.pairing_key_path),
    }
    for key, expected in expected_paths.items():
        value = result.get(key)
        if not isinstance(value, str) or value.casefold() != expected.casefold():
            raise BridgeServiceSecretStorageError(
                f"Bridge service secret storage path evidence differs: {key}"
            )
    for key in (
        "root_acl_exact",
        "credentials_acl_exact",
        "secret_file_acls_exact",
    ):
        if result.get(key) is not True:
            raise BridgeServiceSecretStorageError(
                f"Bridge service secret ACL evidence differs: {key}"
            )
    if result.get("unknown_entries_present") is not False or result.get("reparse_points_present") is not False:
        raise BridgeServiceSecretStorageError(
            "Bridge service secret authority contains unexpected entries or redirects"
        )
    count = result.get("credential_file_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise BridgeServiceSecretStorageError(
            "Bridge service credential file count evidence is invalid"
        )
    if require_pairing_key and result.get("pairing_key_present") is not True:
        raise BridgeServiceSecretStorageError(
            "Bridge service pairing-exchange key is not present"
        )
    if not isinstance(result.get("pairing_key_present"), bool):
        raise BridgeServiceSecretStorageError(
            "Bridge service pairing key presence evidence is invalid"
        )
    return dict(result)


def provision_bridge_service_secret_storage(
    config: BridgeServiceSecretStorageConfig,
    *,
    require_pairing_key: bool = False,
) -> dict[str, object]:
    config.validate()
    result = run_powershell_json(
        build_bridge_service_secret_storage_script(config, reconcile=True),
        timeout_seconds=90,
    )
    return _validate_result(
        result,
        config,
        reconcile=True,
        require_pairing_key=require_pairing_key,
    )


def prove_bridge_service_secret_storage(
    config: BridgeServiceSecretStorageConfig,
    *,
    require_pairing_key: bool = True,
) -> dict[str, object]:
    config.validate()
    result = run_powershell_json(
        build_bridge_service_secret_storage_script(config, reconcile=False),
        timeout_seconds=60,
    )
    return _validate_result(
        result,
        config,
        reconcile=False,
        require_pairing_key=require_pairing_key,
    )
