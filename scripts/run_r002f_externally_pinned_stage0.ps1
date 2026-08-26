[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Stage0ExternalSha256,
  [Parameter(Mandatory=$true)][string]$PythonExecutable,
  [Parameter(Mandatory=$true)][string]$PythonExecutableSha256,
  [Parameter(Mandatory=$true)][string]$GitExecutable,
  [Parameter(Mandatory=$true)][string]$GitExecutableSha256,
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$ReviewedCommit,
  [Parameter(Mandatory=$true)][string]$TargetRelativePath,
  [Parameter(Mandatory=$true)][string]$TargetGitBlobSha1,
  [Parameter(Mandatory=$true)][string]$ProofPath,
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$TargetArgs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Require-Sha256([string]$Value, [string]$Label) {
  if ($Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Label must be canonical lowercase SHA-256" }
  return $Value
}
function Require-Sha1([string]$Value, [string]$Label) {
  if ($Value -cnotmatch '^[0-9a-f]{40}$') { throw "$Label must be canonical lowercase SHA-1" }
  return $Value
}
function Full-Path([string]$Value) {
  return [System.IO.Path]::GetFullPath($Value)
}
function Assert-NoReparseChain([string]$Path, [string]$Label) {
  $full = Full-Path $Path
  $root = [System.IO.Path]::GetPathRoot($full)
  $relative = $full.Substring($root.Length)
  $current = $root
  foreach ($part in @($relative.Split([System.IO.Path]::DirectorySeparatorChar, [System.StringSplitOptions]::RemoveEmptyEntries))) {
    $current = [System.IO.Path]::Combine($current, $part)
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label traverses a reparse point"
      }
    }
  }
}
function Open-PinnedRead([string]$Path, [string]$Label) {
  $full = Full-Path $Path
  Assert-NoReparseChain $full $Label
  if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "$Label is missing" }
  $stream = [System.IO.FileStream]::new(
    $full,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  if ($stream.Length -le 0 -or $stream.Length -gt 536870912) {
    $stream.Dispose()
    throw "$Label size is outside supported bounds"
  }
  Assert-NoReparseChain $full $Label
  return $stream
}
function Hex([byte[]]$Bytes) {
  return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}
function Stream-Sha256([System.IO.FileStream]$Stream) {
  $Stream.Position = 0
  $algorithm = [System.Security.Cryptography.SHA256]::Create()
  try { return (Hex ($algorithm.ComputeHash($Stream))) }
  finally { $algorithm.Dispose(); $Stream.Position = 0 }
}
function Stream-GitBlobSha1([System.IO.FileStream]$Stream) {
  $Stream.Position = 0
  $algorithm = [System.Security.Cryptography.SHA1]::Create()
  try {
    $header = [System.Text.Encoding]::ASCII.GetBytes(('blob ' + [string]$Stream.Length + [char]0))
    [void]$algorithm.TransformBlock($header, 0, $header.Length, $header, 0)
    $buffer = New-Object byte[] 1048576
    while (($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      [void]$algorithm.TransformBlock($buffer, 0, $read, $buffer, 0)
    }
    [void]$algorithm.TransformFinalBlock((New-Object byte[] 0), 0, 0)
    return (Hex $algorithm.Hash)
  } finally { $algorithm.Dispose(); $Stream.Position = 0 }
}
function Invoke-ReviewedGit([string[]]$Arguments) {
  $all = @('-c','core.fsmonitor=false','-c','core.untrackedCache=false','-C',$script:Repo) + $Arguments
  $output = @(& $script:Git @all)
  if ($LASTEXITCODE -ne 0) { throw 'stage-0 Git authority command failed' }
  return $output
}
function Same-Path([string]$Left, [string]$Right) {
  return ([string]::Equals((Full-Path $Left), (Full-Path $Right), [System.StringComparison]::OrdinalIgnoreCase))
}

if ($env:OS -ne 'Windows_NT') { throw 'R002F stage-0 production authority is Windows-only' }

$Stage0ExternalSha256 = Require-Sha256 $Stage0ExternalSha256 'stage-0 external SHA-256'
$PythonExecutableSha256 = Require-Sha256 $PythonExecutableSha256 'Python executable SHA-256'
$GitExecutableSha256 = Require-Sha256 $GitExecutableSha256 'Git executable SHA-256'
$ReviewedCommit = Require-Sha1 $ReviewedCommit 'reviewed commit'
$TargetGitBlobSha1 = Require-Sha1 $TargetGitBlobSha1 'target Git blob SHA-1'

$script:Repo = Full-Path $RepoRoot
$script:Git = Full-Path $GitExecutable
$python = Full-Path $PythonExecutable
$stage0 = Full-Path $PSCommandPath
$proof = Full-Path $ProofPath
Assert-NoReparseChain $script:Repo 'reviewed repo'
if (-not (Test-Path -LiteralPath $script:Repo -PathType Container)) { throw 'reviewed repo root is missing' }
if (Test-Path -LiteralPath $proof) { throw 'stage-0 proof path must be create-only' }
Assert-NoReparseChain ([System.IO.Path]::GetDirectoryName($proof)) 'stage-0 proof parent'
if (-not (Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($proof)) -PathType Container)) {
  throw 'stage-0 proof parent must exist'
}
if ((Full-Path $proof).StartsWith($script:Repo + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'stage-0 proof must be outside reviewed checkout'
}

foreach ($item in @(Get-ChildItem Env:)) {
  $name = [string]$item.Name
  if ($name.StartsWith('GIT_', [System.StringComparison]::OrdinalIgnoreCase) -or
      $name.StartsWith('PYTHON', [System.StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
  }
}
$env:GIT_NO_REPLACE_OBJECTS = '1'
$env:GIT_OPTIONAL_LOCKS = '0'
$env:PYTHONNOUSERSITE = '1'

$pins = New-Object 'System.Collections.Generic.List[System.IO.FileStream]'
$tracked = New-Object 'System.Collections.Generic.List[object]'
try {
  $stage0Stream = Open-PinnedRead $stage0 'stage-0 artifact'; $pins.Add($stage0Stream)
  if ((Stream-Sha256 $stage0Stream) -cne $Stage0ExternalSha256) { throw 'stage-0 SHA-256 differs from external authority' }

  $pythonStream = Open-PinnedRead $python 'reviewed Python executable'; $pins.Add($pythonStream)
  if ((Stream-Sha256 $pythonStream) -cne $PythonExecutableSha256) { throw 'Python SHA-256 differs from external authority' }

  $gitStream = Open-PinnedRead $script:Git 'reviewed Git executable'; $pins.Add($gitStream)
  if ((Stream-Sha256 $gitStream) -cne $GitExecutableSha256) { throw 'Git SHA-256 differs from external authority' }

  $top = @(Invoke-ReviewedGit @('rev-parse','--show-toplevel'))
  if ($top.Count -ne 1 -or -not (Same-Path ([string]$top[0]) $script:Repo)) { throw 'Git top-level differs from reviewed repo' }
  $head = @(Invoke-ReviewedGit @('rev-parse','--verify','HEAD'))
  if ($head.Count -ne 1 -or ([string]$head[0]).Trim() -cne $ReviewedCommit) { throw 'HEAD differs from reviewed commit' }

  $status = @(Invoke-ReviewedGit @('status','--porcelain=v1','--untracked-files=all','--ignored=matching'))
  if ($status.Count -ne 0) { throw 'reviewed checkout contains modified/untracked/ignored content' }

  $flags = @(Invoke-ReviewedGit @('ls-files','-v'))
  if ($flags.Count -eq 0) { throw 'reviewed index is empty' }
  foreach ($line in $flags) {
    if (-not ([string]$line).StartsWith('H ', [System.StringComparison]::Ordinal)) {
      throw 'reviewed checkout contains non-normal index flags'
    }
  }

  $tree = @{}
  $treeLines = @(Invoke-ReviewedGit @('ls-tree','-r','--full-tree',$ReviewedCommit))
  if ($treeLines.Count -eq 0) { throw 'reviewed commit tree is empty' }
  foreach ($lineObject in $treeLines) {
    $line = [string]$lineObject
    if ($line -cnotmatch '^(100644|100755) blob ([0-9a-f]{40})\t(.+)$') { throw 'reviewed tree line is invalid or unsupported' }
    $mode = $Matches[1]; $blob = $Matches[2]; $relative = $Matches[3]
    if ($relative.StartsWith('/') -or $relative.Contains('\') -or
        ($relative.Split('/') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -ne 0) {
      throw 'reviewed tree path is invalid'
    }
    if ($tree.ContainsKey($relative)) { throw 'reviewed tree contains duplicate path' }
    $tree[$relative] = @($mode,$blob)
  }

  $aggregate = [System.Security.Cryptography.SHA256]::Create()
  try {
    foreach ($relative in @($tree.Keys | Sort-Object)) {
      $expected = [string]$tree[$relative][1]
      $path = Full-Path ([System.IO.Path]::Combine($script:Repo, ($relative -replace '/', [System.IO.Path]::DirectorySeparatorChar)))
      if (-not $path.StartsWith($script:Repo + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'tracked path escapes reviewed repo'
      }
      $stream = Open-PinnedRead $path ('tracked file ' + $relative); $pins.Add($stream)
      if ((Stream-GitBlobSha1 $stream) -cne $expected) { throw ('tracked bytes differ from reviewed blob: ' + $relative) }
      $tracked.Add([pscustomobject]@{ Relative=$relative; Blob=$expected; Stream=$stream })
      $record = [System.Text.Encoding]::UTF8.GetBytes($relative + [char]0 + $expected + [char]0)
      [void]$aggregate.TransformBlock($record,0,$record.Length,$record,0)
    }
    [void]$aggregate.TransformFinalBlock((New-Object byte[] 0),0,0)
    $treeAggregate = Hex $aggregate.Hash
  } finally { $aggregate.Dispose() }

  if (-not $tree.ContainsKey($TargetRelativePath)) { throw 'target entrypoint is not tracked by reviewed commit' }
  if ([string]$tree[$TargetRelativePath][1] -cne $TargetGitBlobSha1) { throw 'target entrypoint blob differs from external authority' }
  $targetRecord = @($tracked | Where-Object { $_.Relative -ceq $TargetRelativePath })
  if ($targetRecord.Count -ne 1 -or (Stream-GitBlobSha1 $targetRecord[0].Stream) -cne $TargetGitBlobSha1) {
    throw 'target entrypoint pinned bytes differ before launch'
  }
  $targetPath = Full-Path ([System.IO.Path]::Combine($script:Repo, ($TargetRelativePath -replace '/', [System.IO.Path]::DirectorySeparatorChar)))

  $stdoutLines = @(& $python '-I' '-B' '-X' 'utf8' $targetPath @TargetArgs)
  $targetExit = $LASTEXITCODE
  if ($targetExit -ne 0 -and $targetExit -ne 2) { throw ('target entrypoint failed with exit code ' + [string]$targetExit) }

  foreach ($record in $tracked) {
    if ((Stream-GitBlobSha1 $record.Stream) -cne [string]$record.Blob) {
      throw ('tracked file changed while pinned: ' + [string]$record.Relative)
    }
  }
  $statusAfter = @(Invoke-ReviewedGit @('status','--porcelain=v1','--untracked-files=all','--ignored=matching'))
  if ($statusAfter.Count -ne 0) { throw 'reviewed checkout changed during target execution' }

  $stdout = ($stdoutLines -join "`n").Trim()
  $component = $null
  if ($stdout.Length -gt 0) {
    if ([System.Text.Encoding]::UTF8.GetByteCount($stdout) -gt 524288) { throw 'target stdout exceeds supported bounds' }
    $component = $stdout | ConvertFrom-Json
    if ($null -eq $component -or $component -isnot [psobject]) { throw 'target stdout must be a JSON object' }
  }
  $componentReady = $false
  if ($null -ne $component -and $null -ne $component.PSObject.Properties['ready']) {
    if ($component.ready -isnot [bool]) { throw 'component ready flag must be boolean' }
    $componentReady = [bool]$component.ready
  }

  $payload = [ordered]@{
    schema_version = 1
    qualification = 'R002F_EXTERNALLY_PINNED_STAGE0'
    status = 'TARGET_COMPLETED_UNDER_STAGE0_AUTHORITY'
    ready = $componentReady
    reviewed_commit = $ReviewedCommit
    stage0_external_sha256 = $Stage0ExternalSha256
    stage0_observed_sha256 = (Stream-Sha256 $stage0Stream)
    python_executable_path = $python
    python_executable_sha256 = $PythonExecutableSha256
    git_executable_path = $script:Git
    git_executable_sha256 = $GitExecutableSha256
    target_relative_path = $TargetRelativePath
    target_git_blob_sha1 = $TargetGitBlobSha1
    tracked_file_count = $tracked.Count
    tracked_tree_aggregate_sha256 = $treeAggregate
    full_tracked_working_tree_blob_match_proven = $true
    tracked_files_pinned_against_write_delete = $true
    git_python_control_environment_sanitized = $true
    target_exit_code = [int]$targetExit
    component_qualification = $(if ($null -ne $component) { [string]$component.qualification } else { $null })
    component_status = $(if ($null -ne $component) { [string]$component.status } else { $null })
    component_ready = $(if ($null -ne $component) { [bool]$componentReady } else { $null })
    external_preexecution_pin_required = $true
    external_preexecution_pin_self_proven = $false
  }
  $json = ($payload | ConvertTo-Json -Compress -Depth 8) + "`n"
  $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
  $streamOut = [System.IO.FileStream]::new($proof,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
  try { $streamOut.Write($bytes,0,$bytes.Length); $streamOut.Flush($true) } finally { $streamOut.Dispose() }
  [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 8))
  if ($componentReady) { exit 0 } else { exit 2 }
}
finally {
  for ($index = $pins.Count - 1; $index -ge 0; $index--) { try { $pins[$index].Dispose() } catch { } }
}
