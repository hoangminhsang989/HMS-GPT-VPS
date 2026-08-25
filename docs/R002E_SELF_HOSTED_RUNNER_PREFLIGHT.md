# R002E Self-Hosted Runner Candidate Preflight

Status: `STAGED_NOT_EXECUTED` on branch `r002e-self-hosted-runner-fallback`.

This preflight is intentionally separate from runner registration and from PR #11. It does not execute tests, package attestation, native SCM mutation, Hyper-V mutation, or managed-guest qualification.

## Authority

Frozen R002E candidate:

`1fc5ad20068444446f154f72ed44eb7ec5a0ee5f`

The preflight scripts refuse any other candidate HEAD and require the candidate worktree to be clean. They also bind the worktree copy of `.github/workflows/ci.yml` to the Git blob stored at the frozen candidate commit.

Because the preflight scripts live on the fallback branch, the fallback checkout itself is **not** the candidate. Prepare a separate detached/clean checkout or worktree of the exact frozen commit and pass that path as `CandidateRoot`.

## Windows preflight

Script:

`scripts/preflight_self_hosted_windows.ps1`

Run from elevated 64-bit Windows PowerShell, while the self-hosted runner is still offline:

```powershell
.\scripts\preflight_self_hosted_windows.ps1 -CandidateRoot 'C:\path\to\detached-r002e-candidate'
```

Required gates include:

- Windows x64;
- elevated PowerShell;
- `git`, `pwsh`, and `sc.exe` present;
- candidate path has no symlink/junction/reparse redirect;
- candidate path is the exact Git top-level directory;
- exact HEAD equals the frozen R002E SHA;
- worktree is clean, including untracked files;
- `git diff --check` is clean;
- the workflow file exists and its worktree bytes hash to the exact Git blob from the frozen commit;
- `pwsh` can execute;
- read-only SCM query succeeds.

A PASS does **not** prove SCM service-create permission. The native Windows SCM qualification must still execute in the real qualification job.

Expected result includes:

```text
ready_for_runner_registration = True
exact_head = 1fc5ad20068444446f154f72ed44eb7ec5a0ee5f
worktree_clean = True
diff_check_clean = True
```

## Linux preflight

Script:

`scripts/preflight_self_hosted_linux.sh`

Run as a non-root user inside the already-reviewed Linux x64 environment, while the runner is still offline:

```bash
bash scripts/preflight_self_hosted_linux.sh /absolute/path/to/detached-r002e-candidate
```

Required gates include:

- Linux x64;
- non-root execution;
- existing `git`, `bash`, `curl`, `tar`, and `python3`;
- candidate path is absolute and does not traverse a symlink;
- candidate path is the exact Git top-level directory;
- exact HEAD equals the frozen R002E SHA;
- worktree is clean, including untracked files;
- `git diff --check` is clean;
- workflow bytes match the exact Git blob from the frozen commit;
- distribution/version is inside the reviewed support floor used by the fallback branch.

Expected result includes:

```text
ready_for_runner_registration=True
exact_head=1fc5ad20068444446f154f72ed44eb7ec5a0ee5f
worktree_clean=True
diff_check_clean=True
```

## Qualification order

1. Prepare the detached exact-head candidate checkout separately from the fallback checkout.
2. Run the OS-specific preflight while the runner is still offline.
3. If preflight fails, do not register or start that runner.
4. If preflight passes, obtain a fresh repository runner registration token and register the transient runner using the fallback setup script.
5. Keep the runner offline except during the reviewed frozen qualification window.
6. Execute the unchanged required matrix/package/native-service semantics.
7. Stop the foreground runner and deregister it with a fresh removal token.

## Proof boundary

Preflight PASS is only host/candidate readiness evidence. It must not be represented as CI PASS or real Hyper-V proof.

The following remain false until separately proven:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`
