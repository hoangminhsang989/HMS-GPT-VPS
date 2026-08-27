# R002F external sealed preparation stage-0 authority

Status: `STAGED_NOT_EXECUTED`.

This stage supersedes the earlier `run_r002f_externally_pinned_stage0.ps1` execution model. The older stage pinned only `python.exe`, `git.exe`, and mutable checkout files. The successor prepares the already-reviewed sealed project/Python/Git closure **before any project Python code is imported**.

## External root of trust

The stage-0 script is not allowed to self-prove its own pre-execution authority.

Reviewed candidate SHA-256:

`3b14890a51b7d51aaac0105d1f3149a85c2c0e9b10208f25b4cc8f61130c787f`

The OS-trusted parent launcher must compare the stage-0 bytes with the externally approved SHA-256 **before starting the child**, keep the exact opened file handle alive with `[IO.FileShare]::Read` for the whole child lifetime, and invoke the absolute OS Windows PowerShell host with `-NoProfile -NonInteractive`.

Example launcher pattern (the surrounding deployment authority supplies all remaining stage-0 arguments):

```powershell
$stage0 = [IO.Path]::GetFullPath($stage0Path)
$expected = $externallyApprovedStage0Sha256
$handle = [IO.FileStream]::new(
  $stage0,
  [IO.FileMode]::Open,
  [IO.FileAccess]::Read,
  [IO.FileShare]::Read
)
try {
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $observed = ([BitConverter]::ToString($sha.ComputeHash($handle))).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
    $handle.Position = 0
  }
  if ($observed -cne $expected) { throw 'stage-0 external SHA-256 mismatch' }

  $system = [Environment]::SystemDirectory
  $powershell = [IO.Path]::Combine($system, 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  & $powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -File $stage0 -Stage0ExternalSha256 $expected @stage0Arguments
  $exitCode = $LASTEXITCODE
} finally {
  $handle.Dispose()
}
exit $exitCode
```

The child proof deliberately records:

`external_preexecution_pin_self_proven=false`

because the stage-0 process cannot elevate its own self-hash into proof that the parent performed the external check.

## Authority parent

`AuthorityParent` is an external deployment prerequisite, not something stage-0 reconciles.

It must:

- already exist;
- have a protected DACL;
- be owned by BUILTIN\Administrators;
- contain exactly SYSTEM and BUILTIN\Administrators allow rules with FullControl;
- reside on an OS/deployment-trusted ancestor chain;
- be separate from project/Python/Git source roots and `repo_evidence_root`.

The externally approved stage-0 artifact and all three pinned manifest files must already be direct children of this protected parent before launch. The three sealed destination roots and both proof files must be new direct children of the same parent. Stage-0 never recursively deletes or overwrites a prior root. Partial roots are intentionally preserved on failure for forensics.

## Inputs pinned before preparation

The external deployment authority supplies exact SHA-256 values for:

- the stage-0 script;
- reviewed project execution manifest;
- complete Python runtime manifest;
- complete Git runtime manifest.

The project manifest must bind the exact reviewed commit. Project file records contain path, size, SHA-256 and Git blob SHA-1. Runtime records contain path, size and SHA-256.

A Python runtime containing `pyvenv.cfg` is rejected: the production runtime must be self-contained rather than redirecting `home`/base-prefix to an unsealed interpreter installation.

The Git runtime may not contain `powershell.exe`, `pwsh.exe`, `cmd.exe`, or `python.exe`. A Python runtime containing `pyvenv.cfg` is rejected so it cannot redirect to an unsealed base interpreter.

## Preparation sequence

Stage-0 is PowerShell/.NET-only until sealed Python launch:

1. resolve OS System32 using `[Environment]::SystemDirectory`;
2. replace `PATH`, `PSModulePath`, `SystemRoot`, `windir`, `COMSPEC`, and remove inherited `PYTHON*` / `GIT_*` controls before security cmdlets are used;
3. validate the externally provisioned authority parent;
4. open and pin stage-0 + all three manifest files;
5. verify every manifest SHA-256 and strict expected schema;
6. create three new destination roots;
7. copy only manifest-listed files, create-only, verifying source size/SHA-256 and project Git blob SHA-1 before each copy;
8. verify the complete destination file/directory namespace;
9. apply exact protected read/execute ACLs deepest-child-first, root-last;
10. verify complete bytes + namespace + ACLs again;
11. bound runtime search paths to sealed Git + OS WindowsPowerShell/System32;
12. launch the **sealed Python** entrypoint with `-I -B -X utf8`;
13. execute only `scripts/preflight_r002f_sealed_one_shot_production_qualification.py` from the sealed project root;
14. require a real `R002F_SEALED_EXECUTION_PREFLIGHT` proof, bind its ready flag to exit code, reviewed commit, sealed roots and manifest digests, and record its SHA-256;
15. re-verify all three sealed trees and ACLs after preflight;
16. publish a create-only stage-0 proof.

No Hyper-V, HMSBridge, tunnel, or production command execution occurs in this stage. The called preflight remains observer-only.

## Failure contract

Failures are fail-closed. If possible a create-only failure proof records only the error type and that partial artifacts were preserved. It does not delete arbitrary paths or claim the partial roots as authority.

## Proof boundary

A successful staged run may prove that the sealed preflight was prepared and invoked under externally supplied manifest/hash authority. It does **not** by itself prove:

- `hyperv_guest_proven`;
- `full_bridge_command_flow_proven`;
- `chatgpt_ui_origin_proven`;
- `chatgpt_app_oauth_client_proven`;
- `bootstrap_retired`;
- `pairing_ready`.

Real Windows execution remains a separate qualification gate after fresh committed-byte review.
