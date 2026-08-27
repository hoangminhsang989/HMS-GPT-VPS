[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$LauncherExternalSha256,
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
  [Parameter(Mandatory=$true)][string]$LauncherProofPath,
  [string]$RunDir,
  [string]$PackageRoot,
  [string]$PackageManifest,
  [string]$RuntimeConfig,
  [string]$InstanceRegistry,
  [string]$InstanceRuntimeDir,
  [string]$BridgeDeviceCredential,
  [string]$TrustRootCertificate,
  [string]$ChallengeSourceCommit,
  [string]$ChallengeWorkspacePath,
  [string]$ChallengeExpectedSha256,
  [Nullable[int]]$MaxReconcileSteps,
  [Nullable[double]]$ExternalTimeout,
  [Nullable[double]]$StepTimeout
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$utf8=[Text.UTF8Encoding]::new($false,$true)
$stage0Sha='3b14890a51b7d51aaac0105d1f3149a85c2c0e9b10208f25b4cc8f61130c787f'

function Full([string]$Value){return [IO.Path]::GetFullPath($Value)}
function Same([string]$A,[string]$B){return [string]::Equals((Full $A),(Full $B),[StringComparison]::OrdinalIgnoreCase)}
function Sha256([string]$Value,[string]$Label){if($Value -cnotmatch '^[0-9a-f]{64}$'){throw "$Label must be canonical SHA-256"};return $Value}
function Sha1([string]$Value,[string]$Label){if($Value -cnotmatch '^[0-9a-f]{40}$'){throw "$Label must be canonical SHA-1"};return $Value}
function No-Reparse([string]$Path,[string]$Label){
  $full=Full $Path;$root=[IO.Path]::GetPathRoot($full);$current=$root
  foreach($part in $full.Substring($root.Length).Split([IO.Path]::DirectorySeparatorChar,[StringSplitOptions]::RemoveEmptyEntries)){
    $current=[IO.Path]::Combine($current,$part)
    if([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)){
      $attributes=[IO.File]::GetAttributes($current)
      if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw "$Label traverses reparse point"}
    }
  }
}
function Open-Pin([string]$Path,[string]$Label){
  $full=Full $Path;No-Reparse $full $Label
  if(-not[IO.File]::Exists($full)){throw "$Label is missing"}
  return [IO.FileStream]::new($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
}
function Stream-Sha([IO.FileStream]$Stream){
  $Stream.Position=0;$h=[Security.Cryptography.SHA256]::Create()
  try{return ([BitConverter]::ToString($h.ComputeHash($Stream))).Replace('-','').ToLowerInvariant()}
  finally{$h.Dispose();$Stream.Position=0}
}
function Read-Proof([string]$Path,[string]$Label){
  $stream=Open-Pin $Path $Label
  try{
    if($stream.Length -le 0 -or $stream.Length -gt 196608){throw "$Label size invalid"}
    $sha=Stream-Sha $stream;$bytes=New-Object byte[] ([int]$stream.Length);$stream.Position=0;$offset=0
    while($offset -lt $bytes.Length){$n=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($n -le 0){throw "$Label truncated"};$offset+=$n}
    $obj=($utf8.GetString($bytes))|ConvertFrom-Json
    if($null -eq $obj -or $obj -isnot [psobject]){throw "$Label must be JSON object"}
    return [pscustomobject]@{Stream=$stream;Object=$obj;Sha256=$sha}
  }catch{$stream.Dispose();throw}
}
function Props([psobject]$Object,[string[]]$Names,[string]$Label){
  $a=@($Object.PSObject.Properties|ForEach-Object{[string]$_.Name}|Sort-Object);$b=@($Names|Sort-Object)
  if(($a -join [char]0) -cne ($b -join [char]0)){throw "$Label fields differ"}
}
function Bool-Is([object]$Value,[bool]$Expected,[string]$Label){if($Value -isnot [bool] -or $Value -ne $Expected){throw "$Label boolean differs"}}
function Proof-String([psobject]$Object,[string]$Name){$v=$Object.PSObject.Properties[$Name].Value;if($v -isnot [string]){throw "proof $Name type differs"};return [string]$v}
function Write-Proof([string]$Path,[System.Collections.IDictionary]$Payload){
  $full=Full $Path;if([IO.File]::Exists($full)){throw 'launcher proof must be create-only'}
  $bytes=$utf8.GetBytes((($Payload|ConvertTo-Json -Compress -Depth 8)+"`n"))
  $s=[IO.FileStream]::new($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$s.Write($bytes,0,$bytes.Length);$s.Flush($true)}finally{$s.Dispose()}
}
function Add-Optional([Collections.Generic.List[string]]$List,[string]$Name,[object]$Value){
  if($null -eq $Value -or [string]$Value -eq ''){return}
  $text=[string]$Value
  if($text.StartsWith('-',[StringComparison]::Ordinal)){throw 'optional preflight value must not begin with option prefix'}
  $List.Add($Name);$List.Add($text)
}

if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'R002F external sealed launcher is Windows-only'}
$startupSystem=Full ([Environment]::SystemDirectory)
if([string]::IsNullOrWhiteSpace($startupSystem) -or -not [IO.Directory]::Exists($startupSystem)){throw 'OS System32 authority unavailable'}
$startupPowerShellDir=Full ([IO.Path]::Combine($startupSystem,'WindowsPowerShell','v1.0'))
[Environment]::SetEnvironmentVariable('PATH',([string]::Join([IO.Path]::PathSeparator,@($startupPowerShellDir,$startupSystem))),'Process')
[Environment]::SetEnvironmentVariable('SystemRoot',[IO.Path]::GetDirectoryName($startupSystem),'Process')
[Environment]::SetEnvironmentVariable('windir',[IO.Path]::GetDirectoryName($startupSystem),'Process')
[Environment]::SetEnvironmentVariable('COMSPEC',[IO.Path]::Combine($startupSystem,'cmd.exe'),'Process')
[Environment]::SetEnvironmentVariable('PSModulePath',[IO.Path]::Combine($startupSystem,'WindowsPowerShell','v1.0','Modules'),'Process')
[Environment]::SetEnvironmentVariable('PATHEXT','.EXE','Process')
foreach($nameObject in @([Environment]::GetEnvironmentVariables().Keys)){
  $name=[string]$nameObject
  if($name.StartsWith('PYTHON',[StringComparison]::OrdinalIgnoreCase) -or $name.StartsWith('GIT_',[StringComparison]::OrdinalIgnoreCase)){
    [Environment]::SetEnvironmentVariable($name,$null,'Process')
  }
}
[Environment]::SetEnvironmentVariable('PYTHONNOUSERSITE','1','Process')
$LauncherExternalSha256=Sha256 $LauncherExternalSha256 'launcher external SHA-256'
$ReviewedCommit=Sha1 $ReviewedCommit 'reviewed commit'
$ProjectManifestSha256=Sha256 $ProjectManifestSha256 'project manifest SHA-256'
$PythonManifestSha256=Sha256 $PythonManifestSha256 'Python manifest SHA-256'
$GitManifestSha256=Sha256 $GitManifestSha256 'Git manifest SHA-256'
$authority=Full $AuthorityParent;$launcher=Full $PSCommandPath
$stage0=Full ([IO.Path]::Combine($authority,'run_r002f_external_sealed_preparation_stage0.ps1'))
$launcherProof=Full $LauncherProofPath;$preflightProof=Full $PreflightProofPath;$stage0Proof=Full $Stage0ProofPath
if(-not(Same ([IO.Path]::GetDirectoryName($launcher)) $authority)){throw 'launcher must be direct child of authority parent'}
if(-not(Same ([IO.Path]::GetDirectoryName($stage0)) $authority)){throw 'stage0 must be direct child of authority parent'}
foreach($proof in @($preflightProof,$stage0Proof,$launcherProof)){if(-not(Same ([IO.Path]::GetDirectoryName($proof)) $authority)){throw 'proof must be direct child of authority parent'}}
if((Same $launcherProof $preflightProof) -or (Same $launcherProof $stage0Proof) -or (Same $preflightProof $stage0Proof)){throw 'proof paths must be distinct'}
if([IO.File]::Exists($launcherProof)){throw 'launcher proof must be create-only'}

$launcherPin=$null;$stage0Pin=$null;$preflightPin=$null;$stage0ProofPin=$null
try{
  $launcherPin=Open-Pin $launcher 'launcher artifact'
  if((Stream-Sha $launcherPin) -cne $LauncherExternalSha256){throw 'launcher SHA-256 differs from external authority'}
  $stage0Pin=Open-Pin $stage0 'reviewed stage0 child'
  if((Stream-Sha $stage0Pin) -cne $stage0Sha){throw 'stage0 child SHA-256 differs from reviewed authority'}

  $forward=[Collections.Generic.List[string]]::new()
  Add-Optional $forward '--run-dir' $RunDir;Add-Optional $forward '--package-root' $PackageRoot
  Add-Optional $forward '--package-manifest' $PackageManifest;Add-Optional $forward '--runtime-config' $RuntimeConfig
  Add-Optional $forward '--instance-registry' $InstanceRegistry;Add-Optional $forward '--instance-runtime-dir' $InstanceRuntimeDir
  Add-Optional $forward '--bridge-device-credential' $BridgeDeviceCredential;Add-Optional $forward '--trust-root-certificate' $TrustRootCertificate
  Add-Optional $forward '--challenge-source-commit' $ChallengeSourceCommit;Add-Optional $forward '--challenge-workspace-path' $ChallengeWorkspacePath
  Add-Optional $forward '--challenge-expected-sha256' $ChallengeExpectedSha256
  if($MaxReconcileSteps.HasValue){Add-Optional $forward '--max-reconcile-steps' $MaxReconcileSteps.Value}
  if($ExternalTimeout.HasValue){Add-Optional $forward '--external-timeout' $ExternalTimeout.Value}
  if($StepTimeout.HasValue){Add-Optional $forward '--step-timeout' $StepTimeout.Value}

  $system=Full ([Environment]::SystemDirectory);$powershell=Full ([IO.Path]::Combine($system,'WindowsPowerShell','v1.0','powershell.exe'))
  No-Reparse $powershell 'OS Windows PowerShell';if(-not[IO.File]::Exists($powershell)){throw 'OS Windows PowerShell missing'}
  $child=@(
    '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$stage0,
    '-Stage0ExternalSha256',$stage0Sha,'-ReviewedCommit',$ReviewedCommit,
    '-ProjectSourceRoot',(Full $ProjectSourceRoot),'-ProjectManifestPath',(Full $ProjectManifestPath),'-ProjectManifestSha256',$ProjectManifestSha256,
    '-PythonSourceRoot',(Full $PythonSourceRoot),'-PythonManifestPath',(Full $PythonManifestPath),'-PythonManifestSha256',$PythonManifestSha256,
    '-GitSourceRoot',(Full $GitSourceRoot),'-GitManifestPath',(Full $GitManifestPath),'-GitManifestSha256',$GitManifestSha256,
    '-AuthorityParent',$authority,'-ExecutionRoot',(Full $ExecutionRoot),'-PythonRuntimeRoot',(Full $PythonRuntimeRoot),'-GitRuntimeRoot',(Full $GitRuntimeRoot),
    '-RepoEvidenceRoot',(Full $RepoEvidenceRoot),'-PreflightProofPath',$preflightProof,'-Stage0ProofPath',$stage0Proof
  ) + @($forward)
  $stdout=@(& $powershell @child);$exitCode=$LASTEXITCODE
  if($exitCode -ne 0 -and $exitCode -ne 2){throw ('stage0 child failed with exit code '+[string]$exitCode)}
  if((Stream-Sha $stage0Pin) -cne $stage0Sha){throw 'stage0 child bytes changed across execution'}

  $p=Read-Proof $preflightProof 'sealed preflight proof';$preflightPin=$p.Stream;$po=$p.Object
  Props $po @('schema_version','qualification','status','ready','reviewed_runner_source_commit','repo_evidence_root','execution_root','execution_manifest_sha256','python_runtime_root','python_runtime_manifest_sha256','git_runtime_root','git_runtime_manifest_sha256','system_directory','component_preflight_sha256','component_status','missing_authority','host_blockers','authority_blockers','sealed_execution_tree_proven','python_runtime_closure_proven','git_runtime_closure_proven','execution_started','hyperv_mutated','bridge_started','tunnel_started','one_shot_argv') 'preflight proof'
  if(($po.schema_version -isnot [int] -and $po.schema_version -isnot [long]) -or [int64]$po.schema_version -ne 1){throw 'preflight schema differs'}
  if((Proof-String $po 'qualification') -cne 'R002F_SEALED_EXECUTION_PREFLIGHT'){throw 'preflight qualification differs'}
  Bool-Is $po.ready ($exitCode -eq 0) 'preflight ready'
  if((Proof-String $po 'reviewed_runner_source_commit') -cne $ReviewedCommit){throw 'preflight reviewed commit differs'}
  if(-not(Same (Proof-String $po 'repo_evidence_root') (Full $RepoEvidenceRoot))){throw 'preflight repo evidence root differs'}
  if(-not(Same (Proof-String $po 'execution_root') (Full $ExecutionRoot))){throw 'preflight execution root differs'}
  if(-not(Same (Proof-String $po 'python_runtime_root') (Full $PythonRuntimeRoot))){throw 'preflight Python root differs'}
  if(-not(Same (Proof-String $po 'git_runtime_root') (Full $GitRuntimeRoot))){throw 'preflight Git root differs'}
  if(-not(Same (Proof-String $po 'system_directory') $system)){throw 'preflight system directory differs'}
  if((Proof-String $po 'execution_manifest_sha256') -cne $ProjectManifestSha256 -or (Proof-String $po 'python_runtime_manifest_sha256') -cne $PythonManifestSha256 -or (Proof-String $po 'git_runtime_manifest_sha256') -cne $GitManifestSha256){throw 'preflight manifest digest differs'}
  foreach($name in @('sealed_execution_tree_proven','python_runtime_closure_proven','git_runtime_closure_proven')){Bool-Is $po.PSObject.Properties[$name].Value $true ('preflight '+$name)}
  foreach($name in @('execution_started','hyperv_mutated','bridge_started','tunnel_started')){Bool-Is $po.PSObject.Properties[$name].Value $false ('preflight '+$name)}

  $s=Read-Proof $stage0Proof 'stage0 proof';$stage0ProofPin=$s.Stream;$so=$s.Object
  Props $so @('schema_version','qualification','status','ready','reviewed_commit','stage0_external_sha256','stage0_observed_sha256','project_manifest_sha256','python_runtime_manifest_sha256','git_runtime_manifest_sha256','authority_parent','execution_root','python_runtime_root','git_runtime_root','repo_evidence_root','preflight_proof_path','preflight_proof_sha256','preflight_exit_code','project_tree_sealed','python_runtime_sealed','git_runtime_sealed','external_preexecution_pin_required','external_preexecution_pin_self_proven','execution_started','hyperv_mutated','bridge_started','tunnel_started') 'stage0 proof'
  if(($so.schema_version -isnot [int] -and $so.schema_version -isnot [long]) -or [int64]$so.schema_version -ne 1){throw 'stage0 proof schema differs'}
  if((Proof-String $so 'qualification') -cne 'R002F_EXTERNAL_SEALED_PREPARATION_STAGE0'){throw 'stage0 proof qualification differs'}
  Bool-Is $so.ready ($exitCode -eq 0) 'stage0 ready'
  if($so.preflight_exit_code -isnot [int] -and $so.preflight_exit_code -isnot [long]){throw 'stage0 proof preflight exit type differs'}
  if([int64]$so.preflight_exit_code -ne [int64]$exitCode){throw 'stage0 proof preflight exit differs'}
  if((Proof-String $so 'reviewed_commit') -cne $ReviewedCommit){throw 'stage0 proof reviewed commit differs'}
  if((Proof-String $so 'stage0_external_sha256') -cne $stage0Sha -or (Proof-String $so 'stage0_observed_sha256') -cne $stage0Sha){throw 'stage0 proof child digest differs'}
  if((Proof-String $so 'project_manifest_sha256') -cne $ProjectManifestSha256 -or (Proof-String $so 'python_runtime_manifest_sha256') -cne $PythonManifestSha256 -or (Proof-String $so 'git_runtime_manifest_sha256') -cne $GitManifestSha256){throw 'stage0 proof manifest digest differs'}
  if(-not(Same (Proof-String $so 'authority_parent') $authority) -or -not(Same (Proof-String $so 'execution_root') (Full $ExecutionRoot)) -or -not(Same (Proof-String $so 'python_runtime_root') (Full $PythonRuntimeRoot)) -or -not(Same (Proof-String $so 'git_runtime_root') (Full $GitRuntimeRoot)) -or -not(Same (Proof-String $so 'repo_evidence_root') (Full $RepoEvidenceRoot)) -or -not(Same (Proof-String $so 'preflight_proof_path') $preflightProof)){throw 'stage0 proof path binding differs'}
  if((Proof-String $so 'preflight_proof_sha256') -cne [string]$p.Sha256){throw 'stage0/preflight proof digest binding differs'}
  foreach($name in @('project_tree_sealed','python_runtime_sealed','git_runtime_sealed','external_preexecution_pin_required')){Bool-Is $so.PSObject.Properties[$name].Value $true ('stage0 '+$name)}
  Bool-Is $so.external_preexecution_pin_self_proven $false 'stage0 external pin self proof'
  foreach($name in @('execution_started','hyperv_mutated','bridge_started','tunnel_started')){Bool-Is $so.PSObject.Properties[$name].Value $false ('stage0 '+$name)}

  $payload=[ordered]@{
    schema_version=1;qualification='R002F_EXTERNAL_SEALED_PREPARATION_LAUNCHER';status='STAGE0_AND_PREFLIGHT_CROSS_VALIDATED';ready=($exitCode -eq 0)
    reviewed_commit=$ReviewedCommit;launcher_external_sha256=$LauncherExternalSha256;launcher_observed_sha256=(Stream-Sha $launcherPin)
    stage0_reviewed_sha256=$stage0Sha;preflight_proof_sha256=[string]$p.Sha256;stage0_proof_sha256=[string]$s.Sha256
    external_launcher_preexecution_pin_required=$true;external_launcher_preexecution_pin_self_proven=$false
    execution_started=$false;hyperv_mutated=$false;bridge_started=$false;tunnel_started=$false
  }
  Write-Proof $launcherProof $payload
  [Console]::Out.Write(($payload|ConvertTo-Json -Compress -Depth 6))
  if($exitCode -eq 0){exit 0}else{exit 2}
}finally{
  foreach($stream in @($stage0ProofPin,$preflightPin,$stage0Pin,$launcherPin)){if($null -ne $stream){try{$stream.Dispose()}catch{}}}
}
