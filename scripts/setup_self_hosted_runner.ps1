#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$RepositoryUrl = "https://github.com/hoangminhsang989/HMS-GPT-VPS",
    [string]$RunnerName = "$env:COMPUTERNAME-HMS-GPT-VPS",
    [string]$InstallRoot = "C:\ProgramData\HMS-GPT-VPS\GitHubRunner"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    throw "HMS self-hosted runner setup failed: $Message"
}

if ($env:OS -ne "Windows_NT") {
    Fail "Windows is required"
}
if ($RepositoryUrl -notmatch '^https://github\.com/[^/]+/[^/]+/?$') {
    Fail "RepositoryUrl must be an https://github.com/OWNER/REPO URL"
}
if ([string]::IsNullOrWhiteSpace($RunnerName)) {
    Fail "RunnerName is required"
}

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
if (Test-Path -LiteralPath $root) {
    $existing = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($existing.Count -ne 0) {
        Fail "InstallRoot must be absent or empty; refusing to replace an existing/partial runner"
    }
} else {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
}

$headers = @{
    Accept = "application/vnd.github+json"
    "User-Agent" = "HMS-GPT-VPS-self-hosted-runner-bootstrap"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$release = Invoke-RestMethod -UseBasicParsing -Headers $headers -Uri "https://api.github.com/repos/actions/runner/releases/latest"
$assets = @($release.assets | Where-Object {
    $_.name -match '^actions-runner-win-x64-[0-9]+\.[0-9]+\.[0-9]+\.zip$'
})
if ($assets.Count -ne 1) {
    Fail "latest actions/runner release must expose exactly one Windows x64 ZIP asset"
}
$asset = $assets[0]
if (-not ($asset.digest -is [string]) -or -not $asset.digest.StartsWith("sha256:", [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail "runner release asset does not expose a SHA-256 digest; refusing unverified download"
}
$expectedSha256 = $asset.digest.Substring(7).ToLowerInvariant()
if ($expectedSha256 -notmatch '^[0-9a-f]{64}$') {
    Fail "runner release SHA-256 digest is malformed"
}
if (-not ($asset.browser_download_url -is [string]) -or $asset.browser_download_url -notmatch '^https://github\.com/actions/runner/releases/download/') {
    Fail "runner release download URL is outside the approved actions/runner release namespace"
}

$archive = Join-Path $root "actions-runner.zip"
Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $archive
$actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    Fail "downloaded runner archive SHA-256 mismatch"
}

Expand-Archive -LiteralPath $archive -DestinationPath $root
Remove-Item -LiteralPath $archive -Force
$configCmd = Join-Path $root "config.cmd"
$runCmd = Join-Path $root "run.cmd"
if (-not (Test-Path -LiteralPath $configCmd -PathType Leaf) -or -not (Test-Path -LiteralPath $runCmd -PathType Leaf)) {
    Fail "runner archive is missing config.cmd or run.cmd"
}

Push-Location $root
try {
    $configArgs = @(
        "--unattended",
        "--url", $RepositoryUrl,
        "--token", $registrationToken,
        "--name", $RunnerName,
        "--labels", "hms-gpt-vps",
        "--work", "_work",
        "--runasservice",
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
$serviceFile = Join-Path $root ".service"
foreach ($required in @($runnerConfig, $credentialConfig, $serviceFile)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Fail "runner registration did not publish required local state: $required"
    }
}

$serviceName = (Get-Content -LiteralPath $serviceFile -Raw -ErrorAction Stop).Trim()
if ([string]::IsNullOrWhiteSpace($serviceName)) {
    Fail "runner .service file is empty"
}
$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
    Start-Service -Name $serviceName -ErrorAction Stop
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    $service.Refresh()
}
if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
    Fail "runner Windows service did not reach Running"
}

[pscustomobject]@{
    ready = $true
    repository = $RepositoryUrl
    runner_name = $RunnerName
    install_root = $root
    service_name = $serviceName
    service_status = $service.Status.ToString()
    custom_label = "hms-gpt-vps"
    automatic_updates_disabled = $true
    update_deadline_policy = "manually update within 30 days of each new actions/runner release"
}
