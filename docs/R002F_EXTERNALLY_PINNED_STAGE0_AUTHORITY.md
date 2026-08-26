# R002F externally pinned stage-0 authority

Status: `STAGED_NOT_EXECUTED`.

This tranche defines the pre-project-import trust boundary for the R002F Windows one-shot qualification. It does **not** authorize a Windows/Hyper-V production run by itself.

## Frozen stage-0 bytes

The reviewed stage-0 artifact is `scripts/run_r002f_externally_pinned_stage0.ps1` with:

- Git blob SHA-1: `4316675820ed937a4a04b9d99ea07619d0939757`
- SHA-256: `b2c15627e2264b950d0a64e8bb4224eb7540d13ef3f176237808b78a3af1a504`

The SHA-256 is computed from the exact bytes whose Git blob ID is shown above. A mismatch in either digest is a hard failure.

## Root-of-trust boundary

The stage-0 file must be copied outside the mutable reviewed checkout into a non-reparse authority directory whose write/delete authority is restricted to the trusted administrator/SYSTEM boundary. Do not execute the copy in the checkout directly.

The external launcher is an **inline command executed by OS-trusted Windows PowerShell 5.1**, not another mutable project script. Invoke the system PowerShell by absolute path with `-NoProfile -NonInteractive`. Before invoking stage-0, the launcher must:

1. open the external stage-0 file read-only with `[System.IO.FileShare]::Read` (therefore no write/delete sharing);
2. compute SHA-256 from that already-open stream and compare it to the frozen SHA-256 above;
3. keep the stage-0 FileStream open across execution of the stage-0 script;
4. pass the same frozen SHA-256 as `-Stage0ExternalSha256`;
5. close the external handle only after stage-0 exits.

A hash-then-close-then-execute sequence is forbidden because it reopens a hash-to-execute replacement race.

The launcher must use the exact system host path:

`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive`

The inline launcher shape is:

```powershell
$expected = 'b2c15627e2264b950d0a64e8bb4224eb7540d13ef3f176237808b78a3af1a504'
$stage0 = [System.IO.Path]::GetFullPath('<OUTSIDE_CHECKOUT>\run_r002f_externally_pinned_stage0.ps1')
$hold = [System.IO.FileStream]::new($stage0,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read)
try {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $observed = (($sha.ComputeHash($hold) | ForEach-Object { $_.ToString('x2') }) -join '')
  } finally { $sha.Dispose(); $hold.Position = 0 }
  if ($observed -cne $expected) { throw 'external stage-0 SHA-256 mismatch' }
  & $stage0 -Stage0ExternalSha256 $expected <PINNED-PYTHON/GIT/REVIEWED-COMMIT/TARGET-ARGS>
  $code = $LASTEXITCODE
  if ($code -ne 0 -and $code -ne 2) { throw "stage-0 failed: $code" }
  exit $code
} finally {
  $hold.Dispose()
}
```

The placeholder arguments are deployment values and must not contain secrets. Python and Git are absolute-path + SHA-256 authorities passed to stage-0. The target path and Git blob SHA-1 must identify the exact reviewed target entrypoint.

## Stage-0 guarantees

Before any project module import, stage-0:

- verifies its observed SHA-256 against the external value;
- opens and holds Python and Git with read-only/no-write/no-delete sharing and verifies their SHA-256 digests;
- removes inherited `GIT_*` and `PYTHON*` controls, then sets `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0`, and `PYTHONNOUSERSITE=1`;
- verifies exact reviewed `HEAD`, clean modified/untracked/ignored status, and normal index flags;
- enumerates the exact reviewed tree and independently recomputes every tracked Git blob SHA-1 from opened file bytes;
- keeps every tracked file handle open across target execution;
- launches target Python with `-I -B -X utf8`, so project imports are isolated and no `__pycache__` is written;
- rehashes every pinned tracked file after target execution and rechecks Git status;
- writes create-only proof outside the checkout.

The proof intentionally records `external_preexecution_pin_self_proven=false`. Stage-0 can report the externally supplied digest and its own observed digest, but it cannot self-prove that the required external pre-execution handle was actually held. That fact belongs to the external launcher/Windows qualification evidence.

## Proof boundary

Until a real Windows run independently proves the external launcher handle, exact PowerShell host, stage-0 digest, Python digest, Git digest, reviewed commit, target blob, and resulting one-shot evidence, these remain false:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `chatgpt_ui_origin_proven=false`
- `chatgpt_app_oauth_client_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`

No GitHub CI, Windows PowerShell, Hyper-V, SCM, DPAPI, OAuth, tunnel, or OpenAI end-to-end execution is claimed by this staged tranche.
