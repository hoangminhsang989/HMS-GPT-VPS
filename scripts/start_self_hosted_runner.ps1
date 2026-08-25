#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$CheckOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallRoot = "C:\ProgramData\HMS-GPT-VPS\GitHubRunner"
$ReparsePoint = [System.IO.FileAttributes]::ReparsePoint

function Fail([string]$Message) {
    throw "HMS self-hosted runner start failed: $Message"
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

$root = [System.IO.Path]::GetFullPath($InstallRoot)
Assert-NoReparsePath $root "runner install"
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    Fail "runner install root is missing"
}
if (Test-Path -LiteralPath (Join-Path $root ".service")) {
    Fail "foreground qualification runner must not be configured as a persistent service"
}

$runnerConfig = Join-Path $root ".runner"
$credentialConfig = Join-Path $root ".credentials"
$runCmd = Join-Path $root "run.cmd"
foreach ($required in @($runnerConfig, $credentialConfig, $runCmd)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Fail "runner state is incomplete: $required"
    }
    Assert-NoReparsePath $required "runner state"
}

if ($CheckOnly) {
    [pscustomobject]@{
        ready_to_start = $true
        foreground = $true
        elevated = $true
        install_root = $root
        run_command = $runCmd
        service_mode = $false
    }
    exit 0
}

Write-Host "HMS self-hosted runner foreground qualification mode"
Write-Host "Keep this elevated console open only for the frozen qualification window."
Write-Host "Stop the runner after the required jobs finish, then remove its GitHub registration."

Push-Location $root
try {
    & $runCmd
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($exitCode -ne 0) {
    Fail "run.cmd exited with code $exitCode"
}
