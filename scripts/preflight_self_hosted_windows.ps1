#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CandidateRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExpectedHead = "1fc5ad20068444446f154f72ed44eb7ec5a0ee5f"
$ExpectedWorkflowPath = ".github/workflows/ci.yml"
$ReparsePoint = [System.IO.FileAttributes]::ReparsePoint

function Fail([string]$Message) {
    throw "HMS Windows self-hosted preflight failed: $Message"
}

function Invoke-Git([string[]]$Arguments) {
    $output = & git -C $script:Root @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "git $($Arguments -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return @($output)
}

function Assert-NoReparsePath([string]$Path, [string]$Label) {
    $current = [System.IO.Path]::GetFullPath($Path)
    while ($true) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band $ReparsePoint) -ne 0) {
                Fail "$Label path traverses a reparse point: $current"
            }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
}

if ($env:OS -ne "Windows_NT") {
    Fail "Windows is required"
}
if (-not [Environment]::Is64BitOperatingSystem) {
    Fail "64-bit Windows is required"
}
if (-not [Environment]::Is64BitProcess) {
    Fail "run preflight from a 64-bit PowerShell process"
}

foreach ($command in @("git", "pwsh", "sc.exe")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        Fail "required command is missing: $command"
    }
}

$script:Root = [System.IO.Path]::GetFullPath($CandidateRoot)
Assert-NoReparsePath $script:Root "candidate checkout"
if (-not (Test-Path -LiteralPath $script:Root -PathType Container)) {
    Fail "CandidateRoot does not exist or is not a directory"
}

$topLevel = (Invoke-Git @("rev-parse", "--show-toplevel"))[0].Trim()
$topLevelFull = [System.IO.Path]::GetFullPath($topLevel)
if (-not [string]::Equals($topLevelFull.TrimEnd('\'), $script:Root.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail "CandidateRoot must be the exact git top-level directory"
}

$head = (Invoke-Git @("rev-parse", "HEAD"))[0].Trim().ToLowerInvariant()
if ($head -ne $ExpectedHead) {
    Fail "candidate HEAD mismatch: expected $ExpectedHead, observed $head"
}

$status = @(Invoke-Git @("status", "--porcelain=v1", "--untracked-files=all"))
if ($status.Count -ne 0 -and -not [string]::IsNullOrWhiteSpace(($status -join ""))) {
    Fail "candidate worktree is not clean"
}

$diffCheck = @(Invoke-Git @("diff", "--check"))
if ($diffCheck.Count -ne 0 -and -not [string]::IsNullOrWhiteSpace(($diffCheck -join ""))) {
    Fail "git diff --check reported output"
}

$workflowFile = Join-Path $script:Root $ExpectedWorkflowPath
Assert-NoReparsePath $workflowFile "candidate workflow"
if (-not (Test-Path -LiteralPath $workflowFile -PathType Leaf)) {
    Fail "candidate workflow file is missing: $ExpectedWorkflowPath"
}

$workflowBlobFromCommit = (Invoke-Git @("rev-parse", "$ExpectedHead`:$ExpectedWorkflowPath"))[0].Trim().ToLowerInvariant()
if ($workflowBlobFromCommit -notmatch '^[0-9a-f]{40}$') {
    Fail "candidate workflow blob id is malformed"
}
$workflowBlobFromWorktree = (Invoke-Git @("hash-object", "--", $ExpectedWorkflowPath))[0].Trim().ToLowerInvariant()
if ($workflowBlobFromWorktree -ne $workflowBlobFromCommit) {
    Fail "worktree workflow bytes differ from the frozen exact-head workflow blob"
}

$pwshVersion = (& pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pwshVersion)) {
    Fail "pwsh execution probe failed"
}

& sc.exe query type= service state= all *> $null
$scmQueryExit = $LASTEXITCODE
if ($scmQueryExit -ne 0) {
    Fail "sc.exe query failed with exit code $scmQueryExit"
}

[pscustomobject]@{
    ready_for_runner_registration = $true
    candidate_root = $script:Root
    exact_head = $head
    workflow_blob = $workflowBlobFromCommit
    worktree_clean = $true
    diff_check_clean = $true
    windows_64bit = $true
    elevated = $true
    pwsh_version = $pwshVersion
    scm_read_probe = $true
    note = "preflight does not prove SCM create rights, tests, package attestation, or Hyper-V guest qualification"
}
