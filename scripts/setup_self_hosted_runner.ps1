#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$RunnerName = "$env:COMPUTERNAME-HMS-GPT-VPS"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepositoryUrl = "https://github.com/hoangminhsang989/HMS-GPT-VPS"
$InstallRoot = "C:\ProgramData\HMS-GPT-VPS\GitHubRunner"
$CustomLabel = "hms-gpt-vps-windows"
$ReparsePoint = [System.IO.FileAttributes]::ReparsePoint

function Fail([string]$Message) {
    throw "HMS self-hosted runner setup failed: $Message"
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
if ($RunnerName -notmatch '^[A-Za-z0-9._-]{1,80}$') {
    Fail "RunnerName must contain only letters, digits, dot, underscore or hyphen and be at most 80 characters"
}

# Windows PowerShell 5.1 may otherwise negotiate an obsolete TLS protocol.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$registrationToken = [Environment]::GetEnvironmentVariable(
    "HMS_GITHUB_RUNNER_TOKEN",
    [EnvironmentVariableTarget]::Process
)
[Environment]::SetEnvironmentVariable(
    "HMS_GITHUB_RUNNER_TOKEN",
    $null,
    [EnvironmentVariableTarget]::Process
)
Remove-Item Env:HMS_GITHUB_RUNNER_TOKEN -ErrorAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($registrationToken)) {
    Fail "set a fresh repository runner registration token in process environment variable HMS_GITHUB_RUNNER_TOKEN"
}

$root = [System.IO.Path]::GetFullPath($InstallRoot)
if ($root.TrimEnd('\') -ine $InstallRoot.TrimEnd('\')) {
    Fail "runner install root canonicalization differs from the fixed HMS authority path"
}
Assert-NoReparsePath $root "runner install"

if (Test-Path -LiteralPath $root) {
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) {
        Fail "runner install root exists but is not a directory"
    }
    $existing = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($existing.Count -ne 0) {
        Fail "runner install root must be absent or empty; refusing to replace an existing/partial runner"
    }
} else {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
}
Assert-NoReparsePath $root "runner install"

$headers = @{
    Accept = "application/vnd.github+json"
    "User-Agent" = "HMS-GPT-VPS-self-hosted-runner-bootstrap"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$release = Invoke-RestMethod -UseBasicParsing -Headers $headers -Uri "https://api.github.com/repos/actions/runner/releases/latest"
if (-not ($release.tag_name -is [string]) -or $release.tag_name -notmatch '^v([0-9]+\.[0-9]+\.[0-9]+)$') {
    Fail "latest actions/runner release tag is malformed"
}
$version = $Matches[1]
$expectedAssetName = "actions-runner-win-x64-$version.zip"
$assets = @($release.assets | Where-Object { $_.name -eq $expectedAssetName })
if ($assets.Count -ne 1) {
    Fail "latest actions/runner release must expose exactly one expected Windows x64 ZIP asset"
}
$asset = $assets[0]
if (-not ($asset.size -is [int64]) -and -not ($asset.size -is [int])) {
    Fail "runner release asset size is not an integer"
}
if ([int64]$asset.size -le 0) {
    Fail "runner release asset size must be positive"
}
if (-not ($asset.digest -is [string]) -or -not $asset.digest.StartsWith("sha256:", [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail "runner release asset does not expose a SHA-256 digest; refusing unverified download"
}
$expectedSha256 = $asset.digest.Substring(7).ToLowerInvariant()
if ($expectedSha256 -notmatch '^[0-9a-f]{64}$') {
    Fail "runner release SHA-256 digest is malformed"
}
$expectedDownloadPrefix = "https://github.com/actions/runner/releases/download/$($release.tag_name)/"
if (-not ($asset.browser_download_url -is [string]) -or -not $asset.browser_download_url.StartsWith($expectedDownloadPrefix, [System.StringComparison]::Ordinal)) {
    Fail "runner release download URL is outside the exact approved actions/runner release"
}
if (-not $asset.browser_download_url.EndsWith("/$expectedAssetName", [System.StringComparison]::Ordinal)) {
    Fail "runner release download URL asset name mismatch"
}

$archive = Join-Path $root "actions-runner.zip"
Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $asset.browser_download_url -OutFile $archive
Assert-NoReparsePath $archive "downloaded runner archive"
$archiveItem = Get-Item -LiteralPath $archive -Force -ErrorAction Stop
if ($archiveItem.PSIsContainer -or [int64]$archiveItem.Length -ne [int64]$asset.size) {
    Fail "downloaded runner archive size mismatch"
}
$actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    Fail "downloaded runner archive SHA-256 mismatch"
}

Expand-Archive -LiteralPath $archive -DestinationPath $root
Remove-Item -LiteralPath $archive -Force
Assert-NoReparsePath $root "expanded runner"

$configCmd = Join-Path $root "config.cmd"
$runCmd = Join-Path $root "run.cmd"
$listener = Join-Path $root "bin\Runner.Listener.exe"
foreach ($required in @($configCmd, $runCmd, $listener)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Fail "runner archive is missing required file: $required"
    }
    Assert-NoReparsePath $required "runner executable"
}

Push-Location $root
try {
    $configArgs = @(
        "--unattended",
        "--url", $RepositoryUrl,
        "--token", $registrationToken,
        "--name", $RunnerName,
        "--labels", $CustomLabel,
        "--work", "_work",
        "--disableupdate"
    )
    & $configCmd @configArgs
    if ($LASTEXITCODE -ne 0) {
        Fail "config.cmd returned exit code $LASTEXITCODE"
    }
} finally {
    $registrationToken = $null
    Pop-Location
}

$runnerConfig = Join-Path $root ".runner"
$credentialConfig = Join-Path $root ".credentials"
foreach ($required in @($runnerConfig, $credentialConfig)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Fail "runner registration did not publish required local state: $required"
    }
    Assert-NoReparsePath $required "runner registration state"
}
if (Test-Path -LiteralPath (Join-Path $root ".service")) {
    Fail "foreground fallback must not install a persistent Windows runner service"
}

[pscustomobject]@{
    registered = $true
    repository = $RepositoryUrl
    runner_name = $RunnerName
    install_root = $root
    custom_label = $CustomLabel
    foreground_required = $true
    run_command = (Join-Path $root "run.cmd")
    automatic_updates_disabled = $true
    update_deadline_policy = "manually refresh the runner within 30 days of each new actions/runner release"
    trust_boundary = "keep runner offline except during one frozen exact-head qualification window"
}
