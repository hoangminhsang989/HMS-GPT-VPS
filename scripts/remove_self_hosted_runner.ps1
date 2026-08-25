#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallRoot = "C:\ProgramData\HMS-GPT-VPS\GitHubRunner"
$ReparsePoint = [System.IO.FileAttributes]::ReparsePoint

function Fail([string]$Message) {
    throw "HMS self-hosted runner removal failed: $Message"
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

$configCmd = Join-Path $root "config.cmd"
$runnerConfig = Join-Path $root ".runner"
$credentialConfig = Join-Path $root ".credentials"
foreach ($required in @($configCmd, $runnerConfig, $credentialConfig)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Fail "runner removal state is incomplete: $required"
    }
    Assert-NoReparsePath $required "runner removal state"
}

$listenerPath = (Join-Path $root "bin\Runner.Listener.exe").ToLowerInvariant()
$running = @(Get-CimInstance Win32_Process -Filter "Name='Runner.Listener.exe'" -ErrorAction Stop | Where-Object {
    $_.ExecutablePath -and $_.ExecutablePath.ToLowerInvariant() -eq $listenerPath
})
if ($running.Count -ne 0) {
    Fail "foreground runner is still running; stop its qualification console before deregistration"
}

$removeToken = [Environment]::GetEnvironmentVariable(
    "HMS_GITHUB_RUNNER_REMOVE_TOKEN",
    [EnvironmentVariableTarget]::Process
)
[Environment]::SetEnvironmentVariable(
    "HMS_GITHUB_RUNNER_REMOVE_TOKEN",
    $null,
    [EnvironmentVariableTarget]::Process
)
Remove-Item Env:HMS_GITHUB_RUNNER_REMOVE_TOKEN -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($removeToken)) {
    Fail "set a fresh repository runner removal token in HMS_GITHUB_RUNNER_REMOVE_TOKEN"
}

Push-Location $root
try {
    & $configCmd remove --token $removeToken
    if ($LASTEXITCODE -ne 0) {
        Fail "config.cmd remove returned exit code $LASTEXITCODE"
    }
} finally {
    $removeToken = $null
    Pop-Location
}

if (Test-Path -LiteralPath $runnerConfig -PathType Leaf) {
    Fail "runner .runner configuration still exists after official removal"
}
if (Test-Path -LiteralPath $credentialConfig -PathType Leaf) {
    Fail "runner .credentials still exists after official removal"
}
Assert-NoReparsePath $root "preserved runner install"

[pscustomobject]@{
    deregistered = $true
    local_root_preserved = $true
    install_root = $root
    filesystem_cleanup_performed = $false
}
