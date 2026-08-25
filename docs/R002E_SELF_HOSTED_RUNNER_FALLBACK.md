# R002E Self-Hosted Windows Runner Fallback

Status: `STAGED_NOT_EXECUTED` on branch `r002e-self-hosted-runner-fallback`. This branch is not part of PR #11 and does not change the existing merge gate.

## Purpose

PR #11 exact head `1fc5ad20068444446f154f72ed44eb7ec5a0ee5f` is blocked by GitHub Actions jobs failing before runner step 1 (`steps=null`, no log blob). Issue #12 tracks the infrastructure blocker. This fallback prepares a temporary repository-level Windows self-hosted runner on the same Windows/Hyper-V host without consuming GitHub-hosted private-repository minutes.

A self-hosted runner does **not** by itself prove the HMS managed Hyper-V guest, Bridge command flow, bootstrap retirement, or pairing readiness.

## Critical security boundary

A self-hosted runner executes workflow code directly on the host. The intended host also controls Hyper-V, so runner access is a material trust boundary.

Therefore:

- Do **not** convert the ordinary `pull_request` workflow into an always-online self-hosted workflow.
- Do **not** treat the custom runner label as an authorization boundary.
- Do **not** leave the runner online between qualification windows.
- Freeze the exact PR head first, review the workflow blob that will run, then connect the runner only for that known qualification attempt.
- Stop/remove the runner after the required jobs complete.
- Never accept an unreviewed commit while the physical runner is online.

GitHub's own self-hosted-runner security guidance warns that self-hosted runner environments can be compromised by workflow code; private repositories reduce public-fork exposure but do not make the machine isolated.

## Bootstrap authority

The Windows setup script is intentionally narrow:

- exact repository: `https://github.com/hoangminhsang989/HMS-GPT-VPS`;
- fixed install root: `C:\ProgramData\HMS-GPT-VPS\GitHubRunner`;
- custom label: `hms-gpt-vps-windows`;
- requires elevated Windows PowerShell;
- rejects symlink/junction/reparse redirects in the install path and runner state;
- refuses to replace a non-empty/previous runner directory;
- registration token is accepted only from process environment variable `HMS_GITHUB_RUNNER_TOKEN`, removed from the parent process environment before configuration, and never written to repository files by the bootstrap;
- release metadata comes from the official `actions/runner` latest-release endpoint;
- release tag, exact Windows x64 asset name, positive asset size, exact release download namespace, SHA-256 digest and downloaded byte length are validated before extraction;
- PowerShell 5.1 is forced to TLS 1.2 for the official GitHub requests;
- automatic runner update is disabled for deterministic qualification, which creates an operator obligation to refresh the runner within GitHub's supported update window;
- the runner is **not installed as a Windows service**.

The foreground choice is deliberate. The native Windows SCM gate needs administrator privileges, while a long-lived runner service materially increases persistence and blast radius. The runner must instead be started from an elevated PowerShell only for the qualification window.

## Activation prerequisites

1. Confirm Issue #12 is still the active CI blocker.
2. Prefer first checking GitHub Billing / Metered usage / Budgets for Actions quota or budget exhaustion.
3. Freeze PR #11 at the exact head intended for qualification; no further pushes while the runner is online.
4. Review `.github/workflows/ci.yml` at that exact head before activation.
5. In repository Settings → Actions → Runners, create a fresh repository-level Windows x64 runner registration token.
6. Use an elevated Windows PowerShell on the intended dedicated runner host.

Registration tokens are time-limited. Do not save one in a `.ps1`, `.env`, GitHub issue, commit, shell history file, or reusable document.

## Register the temporary Windows runner

From a checkout of this fallback branch, in elevated Windows PowerShell:

```powershell
$env:HMS_GITHUB_RUNNER_TOKEN = '<fresh repository runner registration token>'
.\scripts\setup_self_hosted_runner.ps1
```

Expected registration result includes:

```text
registered = True
foreground_required = True
custom_label = hms-gpt-vps-windows
```

A successful registration is still not a proof that GitHub sees the runner as Online/Idle. Confirm the runner entry in repository Settings before routing any job to it.

## Preflight and foreground start

Before connecting the runner for the qualification window:

```powershell
.\scripts\start_self_hosted_runner.ps1 -CheckOnly
```

Expected:

```text
ready_to_start = True
foreground = True
service_mode = False
```

Then, only after the exact head/workflow is frozen and reviewed:

```powershell
.\scripts\start_self_hosted_runner.ps1
```

Keep that elevated console open only while the intended qualification jobs execute.

## Workflow activation policy

Do **not** weaken `.github/workflows/ci.yml` merely to obtain a green badge.

Do not commit a self-hosted selector to PR #11 until the required runners are confirmed available. When activation is actually possible, the workflow change must be one reviewed batched commit and must retain the existing test/package/native-service semantics.

Candidate Windows selector:

```yaml
runs-on: [self-hosted, Windows, X64, hms-gpt-vps-windows]
```

The current full gate also requires Linux Python 3.11/3.12/3.13. A Windows self-hosted runner alone does **not** satisfy that Linux requirement. If GitHub-hosted Linux remains unavailable because of account quota/budget, a separately reviewed Linux self-hosted execution environment is required. Do not silently drop the Linux matrix and do not treat Windows WSL as equivalent unless it is explicitly qualified as the Linux runner environment.

No automatic WSL/Hyper-V/Linux-runner installation is performed by this fallback branch.

## Failure / cleanup policy

If registration fails part-way, do not rerun over the same non-empty directory. Preserve diagnostics, remove the partially registered runner through GitHub's normal runner-removal procedure if registration reached GitHub, clean only the dedicated runner root after confirming ownership, obtain a fresh registration token, then retry.

After qualification:

1. stop the foreground runner;
2. remove its repository registration through the normal GitHub runner-removal procedure;
3. confirm it is no longer Online in repository Settings;
4. only then consider local runner-directory cleanup.

## Real Hyper-V proof remains separate

Even after CI runs successfully on self-hosted infrastructure, project authority remains false until a real managed Hyper-V qualification artifact proves it:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`

PR #11 must remain Draft / DO NOT MERGE until both the required CI execution and the later real guest proof gates are satisfied.
