from __future__ import annotations

from pathlib import Path, PureWindowsPath

from .bridge_service_identity import HMS_BRIDGE_SERVICE_ACCOUNT, require_hms_bridge_service_sid
from .powershell import ps_literal, run_powershell_json


DEFAULT_BRIDGE_OAUTH_INTROSPECTION_SECRET_PATH = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\oauth-introspection-client.service-machine.dpapi"
)
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_RESULT_KEYS = frozenset(
    {
        "ready", "changed", "root", "secret_path", "secret_sha256",
        "root_owner_sid", "secret_owner_sid", "service_sid",
        "root_acl_exact", "secret_acl_exact", "root_reparse_point",
        "secret_reparse_point",
    }
)


class BridgeOAuthIntrospectionSecretStorageError(RuntimeError):
    pass


def _fixed_secret_path(path: Path) -> str:
    if not isinstance(path, Path):
        raise TypeError("OAuth introspection secret path must be pathlib.Path")
    observed = str(PureWindowsPath(str(path)))
    expected = str(PureWindowsPath(str(DEFAULT_BRIDGE_OAUTH_INTROSPECTION_SECRET_PATH)))
    if observed.casefold() != expected.casefold():
        raise BridgeOAuthIntrospectionSecretStorageError(
            "OAuth introspection secret path differs from fixed ProgramData authority"
        )
    return expected


def build_bridge_oauth_introspection_secret_storage_script(
    path: Path = DEFAULT_BRIDGE_OAUTH_INTROSPECTION_SECRET_PATH,
    *,
    reconcile: bool,
) -> str:
    secret_path = ps_literal(_fixed_secret_path(path))
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    system_sid = ps_literal(_SYSTEM_SID)
    administrators_sid = ps_literal(_ADMINISTRATORS_SID)
    reconcile_literal = "$true" if reconcile else "$false"
    return f"""
$ErrorActionPreference = 'Stop'
$secretPath = [System.IO.Path]::GetFullPath({secret_path})
$root = [System.IO.Path]::GetDirectoryName($secretPath)
$serviceAccount = {service_account}
$systemSidText = {system_sid}
$administratorsSidText = {administrators_sid}
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
        throw 'OAuth introspection secret authority traverses a reparse point'
      }}
    }}
  }}
}}
function New-Sid([string]$text) {{ return [System.Security.Principal.SecurityIdentifier]::new($text) }}
function New-Rule($sid, $rights) {{
  return [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid, $rights, [System.Security.AccessControl.AccessControlType]::Allow
  )
}}
function Test-ExactAcl($acl, $expected, [string]$ownerSidText) {{
  if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $ownerSidText) {{ return $false }}
  if (-not $acl.AreAccessRulesProtected) {{ return $false }}
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne $expected.Count) {{ return $false }}
  foreach ($rule in $rules) {{
    if ($rule.IsInherited -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {{ return $false }}
    if ($rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None) {{ return $false }}
    if ($rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {{ return $false }}
    $sid = $rule.IdentityReference.Value
    if (-not $expected.ContainsKey($sid)) {{ return $false }}
    if ([int64]$rule.FileSystemRights -ne [int64]$expected[$sid]) {{ return $false }}
  }}
  return $true
}}

Assert-NoReparseChain $root
Assert-NoReparseChain $secretPath
if (-not (Test-Path -LiteralPath $root -PathType Container)) {{ throw 'OAuth introspection secret root is missing' }}
if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) {{ throw 'OAuth introspection secret is missing' }}
$rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
$secretItem = Get-Item -LiteralPath $secretPath -Force -ErrorAction Stop
if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'OAuth introspection secret root is a reparse point' }}
if (($secretItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'OAuth introspection secret file is a reparse point' }}

$serviceSid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
if (-not $serviceSid.StartsWith('S-1-5-80-')) {{ throw 'HMSBridge virtual account did not resolve to a service SID' }}
$systemSid = New-Sid $systemSidText
$administratorsSid = New-Sid $administratorsSidText
$readerSid = New-Sid $serviceSid
$expectedRoot = @{{}}
$expectedRoot[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$expectedRoot[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$expectedRoot[$serviceSid] = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
$expectedFile = @{{}}
$expectedFile[$systemSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$expectedFile[$administratorsSidText] = [System.Security.AccessControl.FileSystemRights]::FullControl
$expectedFile[$serviceSid] = [System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Synchronize

$beforeSha = (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
$changed = $false
$rootAcl = Get-Acl -LiteralPath $root -ErrorAction Stop
$secretAcl = Get-Acl -LiteralPath $secretPath -ErrorAction Stop
$rootExact = Test-ExactAcl $rootAcl $expectedRoot $administratorsSidText
$secretExact = Test-ExactAcl $secretAcl $expectedFile $administratorsSidText
if ((-not $rootExact -or -not $secretExact) -and -not $reconcile) {{ throw 'OAuth introspection secret ACL differs from exact service authority' }}
if ($reconcile -and -not $rootExact) {{
  $acl = [System.Security.AccessControl.DirectorySecurity]::new()
  $acl.SetAccessRuleProtection($true, $false); $acl.SetOwner($administratorsSid)
  $acl.AddAccessRule((New-Rule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-Rule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-Rule $readerSid ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)))
  Set-Acl -LiteralPath $root -AclObject $acl -ErrorAction Stop; $changed = $true
}}
if ($reconcile -and -not $secretExact) {{
  $acl = [System.Security.AccessControl.FileSecurity]::new()
  $acl.SetAccessRuleProtection($true, $false); $acl.SetOwner($administratorsSid)
  $acl.AddAccessRule((New-Rule $systemSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-Rule $administratorsSid ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-Rule $readerSid ([System.Security.AccessControl.FileSystemRights]::Read)))
  Set-Acl -LiteralPath $secretPath -AclObject $acl -ErrorAction Stop; $changed = $true
}}

Assert-NoReparseChain $root
Assert-NoReparseChain $secretPath
$rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
$secretItem = Get-Item -LiteralPath $secretPath -Force -ErrorAction Stop
$afterSha = (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($afterSha -ne $beforeSha) {{ throw 'OAuth introspection secret content changed during ACL authority check' }}
$rootAcl = Get-Acl -LiteralPath $root -ErrorAction Stop
$secretAcl = Get-Acl -LiteralPath $secretPath -ErrorAction Stop
$rootExact = Test-ExactAcl $rootAcl $expectedRoot $administratorsSidText
$secretExact = Test-ExactAcl $secretAcl $expectedFile $administratorsSidText
if (-not $rootExact -or -not $secretExact) {{ throw 'OAuth introspection secret ACL did not converge to exact authority' }}
[pscustomobject]@{{
  ready = $true; changed = [bool]$changed; root = [string]$root; secret_path = [string]$secretPath
  secret_sha256 = [string]$afterSha
  root_owner_sid = [string]$rootAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  secret_owner_sid = [string]$secretAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  service_sid = [string]$serviceSid; root_acl_exact = [bool]$rootExact; secret_acl_exact = [bool]$secretExact
  root_reparse_point = [bool](($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
  secret_reparse_point = [bool](($secretItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}}
""".strip()


def _validate_storage_evidence(result: dict[str, object], path: Path) -> dict[str, object]:
    if frozenset(result) != _RESULT_KEYS or result.get("ready") is not True:
        raise BridgeOAuthIntrospectionSecretStorageError("OAuth introspection secret storage evidence schema is invalid")
    if not isinstance(result.get("changed"), bool):
        raise BridgeOAuthIntrospectionSecretStorageError("OAuth introspection secret changed evidence is invalid")
    if result.get("root_acl_exact") is not True or result.get("secret_acl_exact") is not True:
        raise BridgeOAuthIntrospectionSecretStorageError("OAuth introspection secret ACL evidence differs")
    if result.get("root_reparse_point") is not False or result.get("secret_reparse_point") is not False:
        raise BridgeOAuthIntrospectionSecretStorageError("OAuth introspection secret authority contains a reparse point")
    expected_path = _fixed_secret_path(path)
    if not isinstance(result.get("secret_path"), str) or str(result["secret_path"]).casefold() != expected_path.casefold():
        raise BridgeOAuthIntrospectionSecretStorageError("OAuth introspection secret path evidence differs")
    expected_root = str(PureWindowsPath(expected_path).parent)
    if not isinstance(result.get("root"), str) or str(result["root"]).casefold() != expected_root.casefold():
        raise BridgeOAuthIntrospectionSecretStorageError("OAuth introspection secret root evidence differs")
    if result.get("root_owner_sid") != _ADMINISTRATORS_SID or result.get("secret_owner_sid") != _ADMINISTRATORS_SID:
        raise BridgeOAuthIntrospectionSecretStorageError("OAuth introspection secret owner differs from authority")
    require_hms_bridge_service_sid(result.get("service_sid"))
    sha = result.get("secret_sha256")
    if not isinstance(sha, str) or len(sha) != 64 or sha != sha.lower() or any(c not in "0123456789abcdef" for c in sha):
        raise BridgeOAuthIntrospectionSecretStorageError("OAuth introspection secret SHA-256 evidence is invalid")
    return dict(result)


def provision_bridge_oauth_introspection_secret_storage(
    path: Path = DEFAULT_BRIDGE_OAUTH_INTROSPECTION_SECRET_PATH,
) -> dict[str, object]:
    return _validate_storage_evidence(
        run_powershell_json(build_bridge_oauth_introspection_secret_storage_script(path, reconcile=True), timeout_seconds=60),
        path,
    )


def prove_bridge_oauth_introspection_secret_storage(
    path: Path = DEFAULT_BRIDGE_OAUTH_INTROSPECTION_SECRET_PATH,
) -> dict[str, object]:
    evidence = _validate_storage_evidence(
        run_powershell_json(build_bridge_oauth_introspection_secret_storage_script(path, reconcile=False), timeout_seconds=30),
        path,
    )
    if evidence["changed"] is not False:
        raise BridgeOAuthIntrospectionSecretStorageError("read-only OAuth introspection secret proof reported mutation")
    return evidence
