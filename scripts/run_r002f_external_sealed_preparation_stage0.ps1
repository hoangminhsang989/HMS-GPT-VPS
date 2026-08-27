[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Stage0ExternalSha256,
  [Parameter(Mandatory=$true)][string]$ReviewedCommit,
  [Parameter(Mandatory=$true)][string]$ProjectSourceRoot,
  [Parameter(Mandatory=$true)][string]$ProjectManifestPath,
  [Parameter(Mandatory=$true)][string]$ProjectManifestSha256,
  [Parameter(Mandatory=$true)][string]$PythonSourceRoot,
  [Parameter(Mandatory=$true)][string]$PythonManifestPath,
  [Parameter(Mandatory=$true)][string]$PythonManifestSha256,
  [Parameter(Mandatory=$true)][string]$GitSourceRoot,
  [Parameter(Mandatory=$true)][string]$GitManifestPath,
  [Parameter(Mandatory=$true)][string]$GitManifestSha256,
  [Parameter(Mandatory=$true)][string]$AuthorityParent,
  [Parameter(Mandatory=$true)][string]$ExecutionRoot,
  [Parameter(Mandatory=$true)][string]$PythonRuntimeRoot,
  [Parameter(Mandatory=$true)][string]$GitRuntimeRoot,
  [Parameter(Mandatory=$true)][string]$RepoEvidenceRoot,
  [Parameter(Mandatory=$true)][string]$PreflightProofPath,
  [Parameter(Mandatory=$true)][string]$Stage0ProofPath,
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$PreflightArgs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$systemSid = 'S-1-5-18'
$adminsSid = 'S-1-5-32-544'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false,$true)

function Require-Sha256([string]$Value,[string]$Label) {
  if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label must be canonical lowercase SHA-256" }
  return $Value
}
function Require-Sha1([string]$Value,[string]$Label) {
  if ($Value -cnotmatch '^[0-9a-f]{40}$') { throw "$Label must be canonical lowercase SHA-1" }
  return $Value
}
function Full-Path([string]$Value) {
  $full=[IO.Path]::GetFullPath($Value)
  $root=[IO.Path]::GetPathRoot($full)
  if($full.Length -gt $root.Length){$full=$full.TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar))}
  return $full
}
function Same-Path([string]$Left,[string]$Right) {
  return [string]::Equals((Full-Path $Left),(Full-Path $Right),[StringComparison]::OrdinalIgnoreCase)
}
function Within([string]$Child,[string]$Parent) {
  $childFull = Full-Path $Child
  $parentFull = (Full-Path $Parent).TrimEnd([IO.Path]::DirectorySeparatorChar)
  return $childFull.StartsWith($parentFull + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
}
function Assert-NoReparseChain([string]$Path,[string]$Label) {
  $full=Full-Path $Path
  $drive=[IO.Path]::GetPathRoot($full)
  $current=$drive
  foreach($part in $full.Substring($drive.Length).Split([IO.Path]::DirectorySeparatorChar,[StringSplitOptions]::RemoveEmptyEntries)) {
    $current=[IO.Path]::Combine($current,$part)
    if(Test-Path -LiteralPath $current) {
      $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label traverses a reparse point" }
    }
  }
}
function Hex([byte[]]$Bytes) { return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '') }
function Stream-Sha256([IO.FileStream]$Stream) {
  $Stream.Position=0
  $algorithm=[Security.Cryptography.SHA256]::Create()
  try { return (Hex ($algorithm.ComputeHash($Stream))) }
  finally { $algorithm.Dispose(); $Stream.Position=0 }
}
function Stream-GitBlobSha1([IO.FileStream]$Stream) {
  $Stream.Position=0
  $algorithm=[Security.Cryptography.SHA1]::Create()
  try {
    $header=[Text.Encoding]::ASCII.GetBytes(('blob '+[string]$Stream.Length+[char]0))
    [void]$algorithm.TransformBlock($header,0,$header.Length,$header,0)
    $buffer=New-Object byte[] 1048576
    while(($read=$Stream.Read($buffer,0,$buffer.Length)) -gt 0) {
      [void]$algorithm.TransformBlock($buffer,0,$read,$buffer,0)
    }
    [void]$algorithm.TransformFinalBlock((New-Object byte[] 0),0,0)
    return (Hex $algorithm.Hash)
  } finally { $algorithm.Dispose(); $Stream.Position=0 }
}
function Open-PinnedRead([string]$Path,[string]$Label,[bool]$AllowEmpty=$true) {
  $full=Full-Path $Path
  Assert-NoReparseChain $full $Label
  if(-not(Test-Path -LiteralPath $full -PathType Leaf)) { throw "$Label is missing" }
  $stream=[IO.FileStream]::new($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  if(((-not $AllowEmpty) -and $stream.Length -le 0) -or $stream.Length -gt 536870912) {
    $stream.Dispose(); throw "$Label size is outside bounds"
  }
  return $stream
}
function Read-PinnedUtf8Json([string]$Path,[string]$ExpectedSha,[string]$Label) {
  $stream=Open-PinnedRead $Path $Label $false
  try {
    if($stream.Length -gt 4194304){throw "$Label exceeds 4 MiB manifest bound"}
    if((Stream-Sha256 $stream) -cne $ExpectedSha) { throw "$Label SHA-256 differs from external authority" }
    $bytes=New-Object byte[] ([int]$stream.Length)
    $stream.Position=0
    $offset=0
    while($offset -lt $bytes.Length) {
      $read=$stream.Read($bytes,$offset,$bytes.Length-$offset)
      if($read -le 0) { throw "$Label read truncated" }
      $offset += $read
    }
    $text=$utf8NoBom.GetString($bytes)
    $object=$text | ConvertFrom-Json
    if($null -eq $object -or $object -isnot [psobject]) { throw "$Label must be a JSON object" }
    return [pscustomobject]@{ Stream=$stream; Object=$object; Bytes=$bytes }
  } catch { $stream.Dispose(); throw }
}
function Read-PinnedUtf8JsonObserved([string]$Path,[string]$Label) {
  $stream=Open-PinnedRead $Path $Label $false
  try {
    if($stream.Length -gt 196608){throw "$Label exceeds 192 KiB proof bound"}
    $observed=Stream-Sha256 $stream
    $bytes=New-Object byte[] ([int]$stream.Length)
    $stream.Position=0
    $offset=0
    while($offset -lt $bytes.Length) {
      $read=$stream.Read($bytes,$offset,$bytes.Length-$offset)
      if($read -le 0) { throw "$Label read truncated" }
      $offset += $read
    }
    $object=($utf8NoBom.GetString($bytes)) | ConvertFrom-Json
    if($null -eq $object -or $object -isnot [psobject]) { throw "$Label must be a JSON object" }
    return [pscustomobject]@{ Stream=$stream; Object=$object; ObservedSha256=$observed }
  } catch { $stream.Dispose(); throw }
}
function Validate-Relative([string]$Relative,[string]$Label) {
  if([string]::IsNullOrWhiteSpace($Relative) -or $Relative.Contains('\') -or $Relative.StartsWith('/')) { throw "$Label is invalid" }
  $parts=@($Relative.Split('/'))
  if($parts.Count -eq 0 -or (@($parts | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' })).Count -ne 0) { throw "$Label is invalid" }
  foreach($part in $parts) {
    if($part.EndsWith(' ') -or $part.EndsWith('.')) { throw "$Label is unsafe on Windows" }
    if($part.IndexOfAny([char[]]'<>:"|?*') -ge 0) { throw "$Label contains forbidden Windows characters" }
    $stem=$part.Split('.')[0].ToUpperInvariant()
    if(@('CON','PRN','AUX','NUL','COM1','COM2','COM3','COM4','COM5','COM6','COM7','COM8','COM9','LPT1','LPT2','LPT3','LPT4','LPT5','LPT6','LPT7','LPT8','LPT9') -contains $stem){throw "$Label uses a reserved Windows name"}
  }
  return $Relative
}
function Expected-Directories([object[]]$Files) {
  $set=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach($file in $Files) {
    $parts=@(([string]$file.path).Split('/'))
    for($i=1;$i -lt $parts.Count;$i++) {
      [void]$set.Add(($parts[0..($i-1)] -join '/'))
    }
  }
  return @($set | Sort-Object)
}
function Require-ExactProperties([psobject]$Object,[string[]]$Names,[string]$Label) {
  $actual=@($Object.PSObject.Properties | ForEach-Object { [string]$_.Name } | Sort-Object)
  $expected=@($Names | Sort-Object)
  if(($actual -join [char]0) -cne ($expected -join [char]0)) { throw "$Label fields differ" }
}
function Require-ManifestShape([psobject]$Manifest,[string]$Kind) {
  if($Kind -eq 'project') {
    Require-ExactProperties $Manifest @('schema_version','reviewed_commit','tree_role','file_count','directory_count','total_size','files') "$Kind manifest"
  } else {
    Require-ExactProperties $Manifest @('schema_version','runtime_role','entrypoint','file_count','directory_count','total_size','files') "$Kind manifest"
  }
  if(($Manifest.schema_version -isnot [int] -and $Manifest.schema_version -isnot [long]) -or [int64]$Manifest.schema_version -ne 1) { throw "$Kind manifest schema differs" }
  foreach($numberName in @('file_count','directory_count','total_size')) {
    $numberValue=$Manifest.PSObject.Properties[$numberName].Value
    if($numberValue -isnot [int] -and $numberValue -isnot [long]) { throw "$Kind manifest $numberName type is invalid" }
  }
  if($null -eq $Manifest.PSObject.Properties['files'] -or $Manifest.files -isnot [System.Array]) { throw "$Kind manifest files are invalid" }
  if([int]$Manifest.file_count -ne @($Manifest.files).Count) { throw "$Kind manifest file_count differs" }
  if([int]$Manifest.file_count -le 0 -or [int]$Manifest.file_count -gt 8192) { throw "$Kind manifest file_count is outside bounds" }
  if([int64]$Manifest.total_size -lt 0 -or [int64]$Manifest.total_size -gt 2147483648) { throw "$Kind manifest total_size is outside bounds" }
  $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $total=[int64]0
  foreach($file in @($Manifest.files)) {
    if($Kind -eq 'project') {
      Require-ExactProperties $file @('path','size','sha256','git_blob_sha1') "$Kind manifest file"
    } else {
      Require-ExactProperties $file @('path','size','sha256') "$Kind manifest file"
    }
    if($file.path -isnot [string] -or $file.sha256 -isnot [string]) { throw "$Kind manifest file text field type is invalid" }
    if($Kind -eq 'project' -and $file.git_blob_sha1 -isnot [string]) { throw 'project manifest Git blob field type is invalid' }
    $relative=Validate-Relative ([string]$file.path) "$Kind manifest path"
    if(-not $seen.Add($relative)) { throw "$Kind manifest contains duplicate/case-colliding path" }
    if($file.size -isnot [int] -and $file.size -isnot [long]) { throw "$Kind manifest file size type is invalid" }
    $size=[int64]$file.size
    if($size -lt 0 -or $size -gt 536870912) { throw "$Kind manifest file size is outside bounds" }
    [void](Require-Sha256 ([string]$file.sha256) "$Kind file SHA-256")
    $total += $size
    if($Kind -eq 'project') { [void](Require-Sha1 ([string]$file.git_blob_sha1) 'project Git blob SHA-1') }
  }
  if($total -ne [int64]$Manifest.total_size) { throw "$Kind manifest total_size differs" }
  $dirs=@(Expected-Directories @($Manifest.files))
  if([int]$Manifest.directory_count -ne $dirs.Count) { throw "$Kind manifest directory_count differs" }
  if($Kind -eq 'project') {
    if($Manifest.tree_role -isnot [string] -or $Manifest.reviewed_commit -isnot [string]) { throw 'project manifest text field type differs' }
    if([string]$Manifest.tree_role -cne 'reviewed-project') { throw 'project manifest role differs' }
    if([string]$Manifest.reviewed_commit -cne $script:Reviewed) { throw 'project manifest reviewed commit differs' }
  } else {
    if($Manifest.runtime_role -isnot [string] -or $Manifest.entrypoint -isnot [string]) { throw "$Kind runtime text field type differs" }
    $wanted=$(if($Kind -eq 'python'){'python-runtime'}else{'git-runtime'})
    if([string]$Manifest.runtime_role -cne $wanted) { throw "$Kind runtime role differs" }
    $entry=[string]$Manifest.entrypoint
    [void](Validate-Relative $entry "$Kind runtime entrypoint")
    $leaf=[IO.Path]::GetFileName($entry)
    $expectedLeaf=$(if($Kind -eq 'python'){'python.exe'}else{'git.exe'})
    if(-not [string]::Equals($leaf,$expectedLeaf,[StringComparison]::OrdinalIgnoreCase)) { throw "$Kind runtime entrypoint differs" }
    if((@($Manifest.files | Where-Object { [string]::Equals([string]$_.path,$entry,[StringComparison]::OrdinalIgnoreCase) })).Count -ne 1) { throw "$Kind runtime entrypoint is absent or ambiguous" }
    if($Kind -eq 'python' -and (@($Manifest.files | Where-Object { [string]::Equals([IO.Path]::GetFileName([string]$_.path),'pyvenv.cfg',[StringComparison]::OrdinalIgnoreCase) })).Count -ne 0) {
      throw 'Python runtime must be self-contained and must not contain pyvenv.cfg'
    }
    if($Kind -eq 'git') {
      foreach($file in @($Manifest.files)) {
        $leafName=[IO.Path]::GetFileName([string]$file.path).ToLowerInvariant()
        if(@('powershell.exe','pwsh.exe','cmd.exe','python.exe') -contains $leafName) { throw 'Git runtime shadows a host executable' }
      }
    }
  }
}
function Require-PreparationParentAcl([string]$Path) {
  Assert-NoReparseChain $Path 'authority parent'
  if(-not(Test-Path -LiteralPath $Path -PathType Container)) { throw 'authority parent is missing' }
  $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
  if(-not $acl.AreAccessRulesProtected) { throw 'authority parent ACL must be protected' }
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $adminsSid) { throw 'authority parent owner differs' }
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if($rules.Count -ne 2) { throw 'authority parent ACL rule count differs' }
  $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
  foreach($rule in $rules) {
    if($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'authority parent ACL contains unsupported rule' }
    if(@($systemSid,$adminsSid) -notcontains $rule.IdentityReference.Value) { throw 'authority parent ACL principal differs' }
    if([int64]$rule.FileSystemRights -ne [int64][Security.AccessControl.FileSystemRights]::FullControl) { throw 'authority parent must grant exact administrators/system FullControl' }
    if($rule.InheritanceFlags -ne $inherit -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None){throw 'authority parent ACL inheritance differs'}
  }
}
function Require-NewDirectChild([string]$Path,[string]$Parent,[string]$Label) {
  $full=Full-Path $Path; $parentFull=Full-Path $Parent
  if(Test-Path -LiteralPath $full) { throw "$Label must be new" }
  if(-not(Same-Path ([IO.Path]::GetDirectoryName($full)) $parentFull)) { throw "$Label must be a direct child of authority parent" }
  Assert-NoReparseChain $parentFull "$Label parent"
  return $full
}
function Set-ReadonlyAcl([string]$Path,[bool]$Directory) {
  $owner=[Security.Principal.SecurityIdentifier]::new($adminsSid)
  if($Directory){$acl=[Security.AccessControl.DirectorySecurity]::new()}else{$acl=[Security.AccessControl.FileSecurity]::new()}
  $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($owner)
  $rights=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
  foreach($sidText in @($systemSid,$adminsSid)) {
    $sid=[Security.Principal.SecurityIdentifier]::new($sidText)
    $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,[Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}
function Test-ReadonlyAcl([string]$Path,[bool]$Directory) {
  $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
  if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $adminsSid){return $false}
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if($rules.Count -ne 2){return $false}
  $wanted=[int64]([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize)
  foreach($rule in $rules){
    if($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){return $false}
    if(@($systemSid,$adminsSid) -notcontains $rule.IdentityReference.Value){return $false}
    if([int64]$rule.FileSystemRights -ne $wanted){return $false}
    if($rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None){return $false}
  }
  return $true
}
function Copy-ManifestTree([string]$Source,[string]$Destination,[psobject]$Manifest,[string]$Kind) {
  $sourceFull=Full-Path $Source; $destFull=Full-Path $Destination
  Assert-NoReparseChain $sourceFull "$Kind source root"
  if(-not(Test-Path -LiteralPath $sourceFull -PathType Container)){throw "$Kind source root is missing"}
  [IO.Directory]::CreateDirectory($destFull) | Out-Null
  foreach($directory in @(Expected-Directories @($Manifest.files) | Sort-Object { $_.Length })) {
    [IO.Directory]::CreateDirectory([IO.Path]::Combine($destFull,($directory -replace '/', [IO.Path]::DirectorySeparatorChar))) | Out-Null
  }
  foreach($file in @($Manifest.files)) {
    $relative=[string]$file.path
    $src=Full-Path ([IO.Path]::Combine($sourceFull,($relative -replace '/', [IO.Path]::DirectorySeparatorChar)))
    $dst=Full-Path ([IO.Path]::Combine($destFull,($relative -replace '/', [IO.Path]::DirectorySeparatorChar)))
    if(-not(Within $src $sourceFull) -or -not(Within $dst $destFull)){throw "$Kind copy path escapes root"}
    $input=Open-PinnedRead $src "$Kind source file $relative" $true
    try {
      if($input.Length -ne [int64]$file.size){throw "$Kind source size differs: $relative"}
      if((Stream-Sha256 $input) -cne [string]$file.sha256){throw "$Kind source SHA-256 differs: $relative"}
      if($Kind -eq 'project' -and (Stream-GitBlobSha1 $input) -cne [string]$file.git_blob_sha1){throw "project source Git blob differs: $relative"}
      $output=[IO.FileStream]::new($dst,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
      try {
        $input.Position=0; $input.CopyTo($output); $output.Flush($true)
      } finally { $output.Dispose() }
    } finally { $input.Dispose() }
  }
}
function Verify-ManifestTree([string]$Root,[psobject]$Manifest,[string]$Kind) {
  $rootFull=Full-Path $Root
  Assert-NoReparseChain $rootFull "$Kind sealed root"
  $files=@(Get-ChildItem -LiteralPath $rootFull -File -Force -Recurse -ErrorAction Stop)
  $dirs=@(Get-ChildItem -LiteralPath $rootFull -Directory -Force -Recurse -ErrorAction Stop)
  if($files.Count -ne [int]$Manifest.file_count -or $dirs.Count -ne [int]$Manifest.directory_count){throw "$Kind sealed namespace count differs"}
  $expectedDirs=@(Expected-Directories @($Manifest.files))
  $actualDirs=@($dirs | ForEach-Object { $_.FullName.Substring($rootFull.Length+1).Replace('\','/') } | Sort-Object)
  if(($actualDirs -join [char]0) -cne ($expectedDirs -join [char]0)){throw "$Kind sealed directory namespace differs"}
  foreach($file in @($Manifest.files)) {
    $relative=[string]$file.path
    $path=Full-Path ([IO.Path]::Combine($rootFull,($relative -replace '/', [IO.Path]::DirectorySeparatorChar)))
    $stream=Open-PinnedRead $path "$Kind sealed file $relative" $true
    try {
      if($stream.Length -ne [int64]$file.size -or (Stream-Sha256 $stream) -cne [string]$file.sha256){throw "$Kind sealed bytes differ: $relative"}
      if($Kind -eq 'project' -and (Stream-GitBlobSha1 $stream) -cne [string]$file.git_blob_sha1){throw "project sealed Git blob differs: $relative"}
    } finally { $stream.Dispose() }
  }
}
function Seal-Tree([string]$Root) {
  $entries=@(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop | Sort-Object { $_.FullName.Length } -Descending)
  foreach($entry in $entries){Set-ReadonlyAcl $entry.FullName ([bool]$entry.PSIsContainer)}
  Set-ReadonlyAcl $Root $true
}
function Verify-SealedAcls([string]$Root) {
  $all=@([pscustomobject]@{FullName=(Full-Path $Root);PSIsContainer=$true}) + @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop)
  foreach($entry in $all){if(-not (Test-ReadonlyAcl $entry.FullName ([bool]$entry.PSIsContainer))){throw 'sealed tree ACL differs'}}
}
function Assert-PreflightArgs([string[]]$Arguments) {
  $reserved=@(
    '--execution-root','--execution-manifest','--execution-manifest-sha256',
    '--python-runtime-root','--python-runtime-manifest','--python-runtime-manifest-sha256',
    '--git-runtime-root','--git-runtime-manifest','--git-runtime-manifest-sha256',
    '--repo-evidence-root','--reviewed-runner-source-commit','--proof','--help','-h'
  )
  $flags=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach($argument in @($Arguments)) {
    if($reserved -contains $argument) { throw 'preflight args attempt to override stage-0 sealed authority' }
    if($argument.StartsWith('--',[StringComparison]::Ordinal) -and -not $flags.Add($argument)){throw 'preflight args contain duplicate option'}
  }
}
function Write-ProofCreateOnly([string]$Path,[System.Collections.IDictionary]$Payload) {
  $full=Full-Path $Path
  if(Test-Path -LiteralPath $full){throw 'stage-0 proof path must be create-only'}
  $json=($Payload | ConvertTo-Json -Compress -Depth 8)+"`n"
  $bytes=$utf8NoBom.GetBytes($json)
  $out=[IO.FileStream]::new($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$out.Write($bytes,0,$bytes.Length);$out.Flush($true)}finally{$out.Dispose()}
}

if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'R002F sealed preparation stage-0 is Windows-only'}
$osSystem=Full-Path ([Environment]::SystemDirectory)
if([string]::IsNullOrWhiteSpace($osSystem) -or -not [IO.Directory]::Exists($osSystem)){throw 'OS System32 authority unavailable'}
$osPowerShell=Full-Path ([IO.Path]::Combine($osSystem,'WindowsPowerShell','v1.0'))
[Environment]::SetEnvironmentVariable('PATH',([string]::Join([IO.Path]::PathSeparator,@($osPowerShell,$osSystem))),'Process')
[Environment]::SetEnvironmentVariable('SystemRoot',[IO.Path]::GetDirectoryName($osSystem),'Process')
[Environment]::SetEnvironmentVariable('windir',[IO.Path]::GetDirectoryName($osSystem),'Process')
[Environment]::SetEnvironmentVariable('COMSPEC',[IO.Path]::Combine($osSystem,'cmd.exe'),'Process')
[Environment]::SetEnvironmentVariable('PSModulePath',[IO.Path]::Combine($osSystem,'WindowsPowerShell','v1.0','Modules'),'Process')
foreach($nameObject in @([Environment]::GetEnvironmentVariables().Keys)){
  $name=[string]$nameObject
  if($name.StartsWith('PYTHON',[StringComparison]::OrdinalIgnoreCase) -or $name.StartsWith('GIT_',[StringComparison]::OrdinalIgnoreCase)){
    [Environment]::SetEnvironmentVariable($name,$null,'Process')
  }
}
[Environment]::SetEnvironmentVariable('PYTHONNOUSERSITE','1','Process')
[Environment]::SetEnvironmentVariable('PATHEXT','.EXE','Process')
foreach($secretName in @('HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME','HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD')){
  $secretValue=[Environment]::GetEnvironmentVariable($secretName,'Process')
  if(-not [string]::IsNullOrEmpty($secretValue)){throw 'bootstrap secret environment must be absent during sealed preparation/preflight'}
}
Assert-NoReparseChain $osSystem 'OS System32'
Assert-NoReparseChain $osPowerShell 'OS Windows PowerShell'
if(-not(Test-Path -LiteralPath $osPowerShell -PathType Container)){throw 'OS Windows PowerShell directory is missing'}
Assert-PreflightArgs $PreflightArgs

$script:Reviewed=Require-Sha1 $ReviewedCommit 'reviewed commit'
$Stage0ExternalSha256=Require-Sha256 $Stage0ExternalSha256 'stage-0 external SHA-256'
$ProjectManifestSha256=Require-Sha256 $ProjectManifestSha256 'project manifest SHA-256'
$PythonManifestSha256=Require-Sha256 $PythonManifestSha256 'Python manifest SHA-256'
$GitManifestSha256=Require-Sha256 $GitManifestSha256 'Git manifest SHA-256'

$stage0=Full-Path $PSCommandPath
$authority=Full-Path $AuthorityParent
$execution=Require-NewDirectChild $ExecutionRoot $authority 'execution root'
$pythonRoot=Require-NewDirectChild $PythonRuntimeRoot $authority 'Python runtime root'
$gitRoot=Require-NewDirectChild $GitRuntimeRoot $authority 'Git runtime root'
$repoEvidence=Full-Path $RepoEvidenceRoot
$preflightProof=Full-Path $PreflightProofPath
$stage0Proof=Full-Path $Stage0ProofPath
Require-PreparationParentAcl $authority
if(-not(Same-Path ([IO.Path]::GetDirectoryName($stage0)) $authority)){throw 'stage-0 artifact must be a direct child of authority parent'}
foreach($manifestPath in @($ProjectManifestPath,$PythonManifestPath,$GitManifestPath)){
  if(-not(Same-Path ([IO.Path]::GetDirectoryName((Full-Path $manifestPath))) $authority)){throw 'manifest files must be direct children of authority parent'}
}
if((Same-Path $execution $pythonRoot) -or (Same-Path $execution $gitRoot) -or (Same-Path $pythonRoot $gitRoot)){throw 'sealed destination roots must be distinct'}
foreach($sourceRoot in @($ProjectSourceRoot,$PythonSourceRoot,$GitSourceRoot,$repoEvidence)){
  $sourceFull=Full-Path $sourceRoot
  if((Within $authority $sourceFull) -or (Within $sourceFull $authority) -or (Same-Path $authority $sourceFull)){throw 'authority parent must be separate from mutable/source roots'}
}
if(Same-Path $preflightProof $stage0Proof){throw 'preflight and stage-0 proof paths must differ'}
foreach($left in @($execution,$pythonRoot,$gitRoot)){
  foreach($right in @($execution,$pythonRoot,$gitRoot)){
    if(-not(Same-Path $left $right) -and ((Within $left $right) -or (Within $right $left))){throw 'sealed destination roots must not nest'}
  }
  if((Within $left $repoEvidence) -or (Within $repoEvidence $left)){throw 'sealed destination roots must be separate from repo evidence'}
}
foreach($manifestPath in @($ProjectManifestPath,$PythonManifestPath,$GitManifestPath)){
  $m=Full-Path $manifestPath
  foreach($root in @($execution,$pythonRoot,$gitRoot)){if((Within $m $root) -or (Same-Path $m $root)){throw 'manifest path must be outside sealed roots'}}
}
foreach($proofPath in @($preflightProof,$stage0Proof)){
  if(Test-Path -LiteralPath $proofPath){throw 'proof path must be create-only'}
  if(-not(Same-Path ([IO.Path]::GetDirectoryName($proofPath)) $authority)){throw 'proof path must be a direct child of authority parent'}
}

$manifestPins=New-Object 'System.Collections.Generic.List[System.IO.FileStream]'
$stage0Pin=$null
try {
  $stage0Pin=Open-PinnedRead $stage0 'stage-0 artifact' $false
  if((Stream-Sha256 $stage0Pin) -cne $Stage0ExternalSha256){throw 'stage-0 observed SHA-256 differs from external authority'}

  $projectRead=Read-PinnedUtf8Json $ProjectManifestPath $ProjectManifestSha256 'project manifest';$manifestPins.Add($projectRead.Stream)
  $pythonRead=Read-PinnedUtf8Json $PythonManifestPath $PythonManifestSha256 'Python manifest';$manifestPins.Add($pythonRead.Stream)
  $gitRead=Read-PinnedUtf8Json $GitManifestPath $GitManifestSha256 'Git manifest';$manifestPins.Add($gitRead.Stream)
  $projectManifest=$projectRead.Object;$pythonManifest=$pythonRead.Object;$gitManifest=$gitRead.Object
  Require-ManifestShape $projectManifest 'project'
  Require-ManifestShape $pythonManifest 'python'
  Require-ManifestShape $gitManifest 'git'

  Copy-ManifestTree $ProjectSourceRoot $execution $projectManifest 'project'
  Copy-ManifestTree $PythonSourceRoot $pythonRoot $pythonManifest 'python'
  Copy-ManifestTree $GitSourceRoot $gitRoot $gitManifest 'git'
  Verify-ManifestTree $execution $projectManifest 'project'
  Verify-ManifestTree $pythonRoot $pythonManifest 'python'
  Verify-ManifestTree $gitRoot $gitManifest 'git'

  Seal-Tree $execution;Seal-Tree $pythonRoot;Seal-Tree $gitRoot
  Verify-SealedAcls $execution;Verify-SealedAcls $pythonRoot;Verify-SealedAcls $gitRoot
  Verify-ManifestTree $execution $projectManifest 'project'
  Verify-ManifestTree $pythonRoot $pythonManifest 'python'
  Verify-ManifestTree $gitRoot $gitManifest 'git'
  Verify-SealedAcls $execution;Verify-SealedAcls $pythonRoot;Verify-SealedAcls $gitRoot

  $pythonEntry=Full-Path ([IO.Path]::Combine($pythonRoot,(([string]$pythonManifest.entrypoint) -replace '/', [IO.Path]::DirectorySeparatorChar)))
  $gitEntry=Full-Path ([IO.Path]::Combine($gitRoot,(([string]$gitManifest.entrypoint) -replace '/', [IO.Path]::DirectorySeparatorChar)))
  $preflightScript=Full-Path ([IO.Path]::Combine($execution,'scripts','preflight_r002f_sealed_one_shot_production_qualification.py'))
  if(-not(Test-Path -LiteralPath $preflightScript -PathType Leaf)){throw 'sealed preflight script is absent from project tree'}

  $system=$osSystem
  $powershellDir=$osPowerShell
  $env:PATH=([string]::Join([IO.Path]::PathSeparator,@([IO.Path]::GetDirectoryName($gitEntry),$powershellDir,$system)))
  $env:SystemRoot=[IO.Path]::GetDirectoryName($system)
  $env:windir=$env:SystemRoot
  $env:COMSPEC=[IO.Path]::Combine($system,'cmd.exe')
  $env:PSModulePath=[IO.Path]::Combine($system,'WindowsPowerShell','v1.0','Modules')
  $env:PATHEXT='.EXE'
  $env:PYTHONNOUSERSITE='1';$env:GIT_NO_REPLACE_OBJECTS='1';$env:GIT_OPTIONAL_LOCKS='0';$env:GIT_CONFIG_NOSYSTEM='1';$env:GIT_CONFIG_GLOBAL='NUL'
  $env:GIT_CONFIG_COUNT='2';$env:GIT_CONFIG_KEY_0='core.fsmonitor';$env:GIT_CONFIG_VALUE_0='false';$env:GIT_CONFIG_KEY_1='core.untrackedCache';$env:GIT_CONFIG_VALUE_1='false' 

  $fixed=@(
    '--execution-root',$execution,
    '--execution-manifest',(Full-Path $ProjectManifestPath),
    '--execution-manifest-sha256',$ProjectManifestSha256,
    '--python-runtime-root',$pythonRoot,
    '--python-runtime-manifest',(Full-Path $PythonManifestPath),
    '--python-runtime-manifest-sha256',$PythonManifestSha256,
    '--git-runtime-root',$gitRoot,
    '--git-runtime-manifest',(Full-Path $GitManifestPath),
    '--git-runtime-manifest-sha256',$GitManifestSha256,
    '--repo-evidence-root',$repoEvidence,
    '--reviewed-runner-source-commit',$script:Reviewed,
    '--proof',$preflightProof
  )
  Set-Location -LiteralPath $execution
  $stdout=@(& $pythonEntry '-I' '-B' '-X' 'utf8' $preflightScript @fixed @PreflightArgs)
  $exitCode=$LASTEXITCODE
  if($exitCode -ne 0 -and $exitCode -ne 2){throw ('sealed preflight failed with exit code '+[string]$exitCode)}
  $preflightRead=Read-PinnedUtf8JsonObserved $preflightProof 'sealed preflight proof'
  $manifestPins.Add($preflightRead.Stream)
  $preflightObject=$preflightRead.Object
  Require-ExactProperties $preflightObject @(
    'schema_version','qualification','status','ready','reviewed_runner_source_commit',
    'repo_evidence_root','execution_root','execution_manifest_sha256',
    'python_runtime_root','python_runtime_manifest_sha256','git_runtime_root',
    'git_runtime_manifest_sha256','system_directory','component_preflight_sha256',
    'component_status','missing_authority','host_blockers','authority_blockers',
    'sealed_execution_tree_proven','python_runtime_closure_proven',
    'git_runtime_closure_proven','execution_started','hyperv_mutated',
    'bridge_started','tunnel_started','one_shot_argv'
  ) 'sealed preflight proof'
  if([string]$preflightObject.qualification -cne 'R002F_SEALED_EXECUTION_PREFLIGHT'){throw 'sealed preflight proof qualification differs'}
  if($preflightObject.ready -isnot [bool] -or [bool]$preflightObject.ready -ne ($exitCode -eq 0)){throw 'sealed preflight proof ready/exit binding differs'}
  if([string]$preflightObject.reviewed_runner_source_commit -cne $script:Reviewed){throw 'sealed preflight proof reviewed commit differs'}
  if(-not(Same-Path ([string]$preflightObject.execution_root) $execution)){throw 'sealed preflight proof execution root differs'}
  if(-not(Same-Path ([string]$preflightObject.python_runtime_root) $pythonRoot)){throw 'sealed preflight proof Python root differs'}
  if(-not(Same-Path ([string]$preflightObject.git_runtime_root) $gitRoot)){throw 'sealed preflight proof Git root differs'}
  if([string]$preflightObject.execution_manifest_sha256 -cne $ProjectManifestSha256 -or [string]$preflightObject.python_runtime_manifest_sha256 -cne $PythonManifestSha256 -or [string]$preflightObject.git_runtime_manifest_sha256 -cne $GitManifestSha256){throw 'sealed preflight proof manifest digest differs'}
  if($preflightObject.sealed_execution_tree_proven -isnot [bool] -or $preflightObject.sealed_execution_tree_proven -ne $true -or $preflightObject.python_runtime_closure_proven -ne $true -or $preflightObject.git_runtime_closure_proven -ne $true){throw 'sealed preflight proof closure flags differ'}
  $preflightProofSha256=[string]$preflightRead.ObservedSha256

  Verify-ManifestTree $execution $projectManifest 'project';Verify-SealedAcls $execution
  Verify-ManifestTree $pythonRoot $pythonManifest 'python';Verify-SealedAcls $pythonRoot
  Verify-ManifestTree $gitRoot $gitManifest 'git';Verify-SealedAcls $gitRoot

  $payload=[ordered]@{
    schema_version=1
    qualification='R002F_EXTERNAL_SEALED_PREPARATION_STAGE0'
    status='SEALED_PREFLIGHT_COMPLETED'
    ready=($exitCode -eq 0)
    reviewed_commit=$script:Reviewed
    stage0_external_sha256=$Stage0ExternalSha256
    stage0_observed_sha256=(Stream-Sha256 $stage0Pin)
    project_manifest_sha256=$ProjectManifestSha256
    python_runtime_manifest_sha256=$PythonManifestSha256
    git_runtime_manifest_sha256=$GitManifestSha256
    authority_parent=$authority
    execution_root=$execution
    python_runtime_root=$pythonRoot
    git_runtime_root=$gitRoot
    repo_evidence_root=$repoEvidence
    preflight_proof_path=$preflightProof
    preflight_proof_sha256=$preflightProofSha256
    preflight_exit_code=[int]$exitCode
    project_tree_sealed=$true
    python_runtime_sealed=$true
    git_runtime_sealed=$true
    external_preexecution_pin_required=$true
    external_preexecution_pin_self_proven=$false
    execution_started=$false
    hyperv_mutated=$false
    bridge_started=$false
    tunnel_started=$false
  }
  Write-ProofCreateOnly $stage0Proof $payload
  [Console]::Out.Write(($payload|ConvertTo-Json -Compress -Depth 8))
  if($exitCode -eq 0){exit 0}else{exit 2}
}
catch {
  try {
    if(-not(Test-Path -LiteralPath $stage0Proof)) {
      $failure=[ordered]@{
        schema_version=1
        qualification='R002F_EXTERNAL_SEALED_PREPARATION_STAGE0_FAILURE'
        status='FAILED_CLOSED'
        reviewed_commit=$script:Reviewed
        error_type=$_.Exception.GetType().Name
        partial_artifacts_preserved=$true
        proof_authority=$false
        execution_started=$false
        hyperv_mutated=$false
        bridge_started=$false
        tunnel_started=$false
      }
      Write-ProofCreateOnly $stage0Proof $failure
    }
  } catch {}
  throw
}
finally {
  if($stage0Pin -ne $null){try{$stage0Pin.Dispose()}catch{}}
  for($i=$manifestPins.Count-1;$i -ge 0;$i--){try{$manifestPins[$i].Dispose()}catch{}}
}
