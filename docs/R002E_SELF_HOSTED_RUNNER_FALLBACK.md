# R002E Self-Hosted Windows Runner Fallback

Status: staged on branch `r002e-self-hosted-runner-fallback`; not part of PR #11 and not a replacement for the existing merge gate.

## Purpose

PR #11 exact head `1fc5ad20068444446f154f72ed44eb7ec5a0ee5f` is blocked by GitHub Actions jobs failing before runner step 1 (`steps=null`, no log blob). Issue #12 tracks the blocker. This fallback prepares a repository-level Windows self-hosted runner on the same Windows/Hyper-V host without consuming GitHub-hosted private-repository minutes.

A self-hosted runner does **not** by itself prove the HMS managed Hyper-V guest, Bridge command flow, bootstrap retirement, or pairing readiness.

## Security model

- Use only with the private `hoangminhsang989/HMS-GPT-VPS` repository.
- Runner is repository-level and dedicated to this project.
- Custom label: `hms-gpt-vps`; GitHub also adds the normal `self-hosted`, `Windows`, and `X64` labels.
- Install under `C:\ProgramData\HMS-GPT-VPS\GitHubRunner`, not a user profile.
- The setup script refuses to replace a non-empty/previous runner directory.
- Registration token is read only from process environment variable `HMS_GITHUB_RUNNER_TOKEN`, removed from the parent process environment before configuration, and never written to repository files by this bootstrap.
- Runner release is discovered from the official `actions/runner` latest release, download URL must remain inside the official release namespace, and the ZIP must match the SHA-256 digest exposed by the GitHub release API before extraction.
- Runner is configured as a Windows service.
- Automatic runner self-update is disabled because the fallback prioritizes deterministic service behavior. This creates an operator obligation: update the runner within 30 days of every new `actions/runner` release, and immediately for critical security releases, or GitHub may stop queueing jobs to it.
- Never route untrusted public-fork PR code to this machine. Self-hosted jobs execute with access to the host environment.

## Activation prerequisites

1. Confirm Issue #12 is still the active CI blocker.
2. Prefer first checking GitHub Billing / Metered usage / Budgets for Actions quota or budget exhaustion.
3. In repository Settings → Actions → Runners, create a fresh repository-level Windows x64 runner registration token.
4. Use an elevated Windows PowerShell on the intended dedicated runner host.

Registration tokens are time-limited. Do not save one in a `.ps1`, `.env`, GitHub issue, commit, shell history file, or reusable document.

## Bootstrap

From a checkout of this fallback branch, in elevated Windows PowerShell:

```powershell
$env:HMS_GITHUB_RUNNER_TOKEN = '<fresh repository runner registration token>'
.\scripts\setup_self_hosted_runner.ps1
```

The script must finish with a result containing:

```text
ready = True
service_status = Running
custom_label = hms-gpt-vps
```

If it fails part-way, do not rerun over the same directory. Preserve diagnostics, remove the partially registered runner through the normal GitHub runner-removal procedure if registration reached GitHub, clean the dedicated install root, obtain a fresh registration token, then retry.

## Workflow activation policy

Do **not** weaken `.github/workflows/ci.yml` merely to obtain a green badge.

Once the runner is confirmed Online/Idle in repository Settings, prepare one batched commit for the intended workflow change. Candidate Windows job selector:

```yaml
runs-on: [self-hosted, Windows, X64, hms-gpt-vps]
```

The existing Windows Python 3.11/3.12/3.13 tests, package attestation, and native Windows SCM qualification must still execute and pass.

The current full gate also requires Linux Python 3.11/3.12/3.13. A Windows self-hosted runner alone does not satisfy that Linux requirement. If GitHub-hosted Linux remains unavailable because of account quota/budget, add a dedicated Linux self-hosted runner (or another separately reviewed Linux execution environment) rather than silently dropping the Linux matrix.

## Real Hyper-V proof remains separate

Even after CI runs successfully on self-hosted infrastructure, project authority remains false until a real managed Hyper-V qualification artifact proves it:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`

PR #11 must remain Draft / DO NOT MERGE until both the required CI execution and the later real guest proof gates are satisfied.
