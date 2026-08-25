# R002E Self-Hosted Runner Fallback

Status: `STAGED_NOT_EXECUTED` on branch `r002e-self-hosted-runner-fallback`. This branch is not part of PR #11 and does not change the existing merge gate.

## Purpose

PR #11 exact head `1fc5ad20068444446f154f72ed44eb7ec5a0ee5f` is blocked by GitHub Actions jobs failing before runner step 1 (`steps=null`, no log blob). Issue #12 tracks the infrastructure blocker.

This branch stages transient self-hosted runner bootstraps so the existing Windows and Linux CI matrices can still be executed if GitHub-hosted private-repository minutes/allocation remain unavailable.

A self-hosted runner does **not** by itself prove the HMS managed Hyper-V guest, Bridge command flow, bootstrap retirement, or pairing readiness.

## Critical security boundary

Self-hosted runners execute workflow code directly on their host. The Windows host also controls Hyper-V, so runner access is a material trust boundary.

Rules:

- Do **not** convert the ordinary `pull_request` workflow into an always-online self-hosted workflow.
- Do **not** treat custom runner labels as authorization boundaries.
- Do **not** leave either runner online between qualification windows.
- Freeze the exact PR head first, review the workflow blob that will run, then connect runners only for that known qualification attempt.
- Never accept an unreviewed commit while a physical/self-hosted runner is online.
- Stop/remove runner registrations after the required jobs complete.

GitHub's self-hosted-runner security guidance explicitly warns that workflow code can compromise the self-hosted environment. Private repositories reduce public-fork exposure but do not provide VM isolation.

## Windows runner authority

Files:

- `scripts/setup_self_hosted_runner.ps1`
- `scripts/start_self_hosted_runner.ps1`

Bootstrap properties:

- exact repository: `https://github.com/hoangminhsang989/HMS-GPT-VPS`;
- fixed install root: `C:\ProgramData\HMS-GPT-VPS\GitHubRunner`;
- custom label: `hms-gpt-vps-windows`;
- elevated Windows PowerShell required;
- install path/runner state reject symlink/junction/reparse redirects;
- non-empty previous runner directories are never replaced;
- registration token is accepted only from process environment variable `HMS_GITHUB_RUNNER_TOKEN`, removed from the parent process environment before configuration, and not written to repository files;
- official `actions/runner` release tag, exact Windows x64 asset name, positive asset size, exact release download namespace, SHA-256 digest and downloaded byte length are validated before extraction;
- PowerShell 5.1 uses TLS 1.2 for official GitHub requests;
- automatic update is disabled for deterministic qualification;
- runner is **foreground only**, not a Windows service.

Foreground mode is deliberate. The native Windows SCM gate needs administrator privileges, while a long-lived privileged runner service increases persistence and blast radius.

### Register Windows runner

In elevated Windows PowerShell from this fallback branch:

```powershell
$env:HMS_GITHUB_RUNNER_TOKEN = '<fresh repository runner registration token>'
.\scripts\setup_self_hosted_runner.ps1
```

Expected registration evidence includes:

```text
registered = True
foreground_required = True
custom_label = hms-gpt-vps-windows
```

### Windows preflight/start

```powershell
.\scripts\start_self_hosted_runner.ps1 -CheckOnly
```

Expected:

```text
ready_to_start = True
foreground = True
service_mode = False
```

Then, only during the frozen qualification window:

```powershell
.\scripts\start_self_hosted_runner.ps1
```

## Linux runner authority

Files:

- `scripts/setup_self_hosted_runner_linux.sh`
- `scripts/start_self_hosted_runner_linux.sh`

The Linux fallback is generic and does **not** install WSL, a Linux VM, packages, or a distribution. It must run inside an already-existing, separately reviewed Linux x64 environment.

Reviewed GitHub-supported distro floor:

- Ubuntu 20.04+
- Debian 10+
- RHEL/CentOS/Oracle Linux 8+
- Fedora 29+
- Linux Mint 20+
- openSUSE Leap 15.2+
- SLES 15.2+

Bootstrap properties:

- x64 Linux only;
- must run as a non-root user;
- requires existing `curl`, `python3`, `tar`, `sha256sum`, and `stat`;
- fixed per-user install root: `~/.local/share/hms-gpt-vps/github-runner-linux`;
- symlink redirects in HOME/install state are rejected;
- exact repository: `https://github.com/hoangminhsang989/HMS-GPT-VPS`;
- custom label: `hms-gpt-vps-linux`;
- registration token comes only from process environment variable `HMS_GITHUB_RUNNER_TOKEN` and is unset before external runner execution;
- official `actions/runner` latest release is parsed with Python stdlib JSON;
- exact Linux x64 asset name, official release namespace, positive size and SHA-256 digest are validated before extraction;
- runner is foreground only and never installed as a service.

WSL is **not automatically treated as qualified Linux** by this branch. If WSL is chosen later, the actual distro/version/runtime must independently meet the Linux runner requirements and project acceptance criteria.

### Register Linux runner

Inside the reviewed Linux x64 environment:

```bash
export HMS_GITHUB_RUNNER_TOKEN='<fresh repository runner registration token>'
bash scripts/setup_self_hosted_runner_linux.sh
```

Expected registration evidence includes:

```text
registered=True
foreground_required=True
custom_label=hms-gpt-vps-linux
```

### Linux preflight/start

```bash
bash scripts/start_self_hosted_runner_linux.sh --check-only
```

Then, only during the frozen qualification window:

```bash
bash scripts/start_self_hosted_runner_linux.sh
```

## Activation prerequisites

Before either runner is connected:

1. Confirm Issue #12 remains the active blocker.
2. Prefer first checking GitHub Billing / Metered usage / Budgets.
3. Freeze PR #11 at the exact head intended for qualification; no further pushes while runners are online.
4. Review `.github/workflows/ci.yml` at that exact head.
5. Confirm the required Windows **and** Linux runner environments exist and are healthy.
6. Create fresh repository-level registration tokens only when each runner is ready to register.

Registration tokens are time-limited. Never place one in a script, `.env`, issue, commit, reusable document, or shell history file.

## Workflow activation policy

Do **not** weaken `.github/workflows/ci.yml` merely to obtain a green badge.

Do not commit self-hosted selectors to PR #11 until the corresponding runners are confirmed available. Any activation change must be one reviewed batched commit and must retain the existing semantics:

- Linux Python 3.11 / 3.12 / 3.13
- Windows Python 3.11 / 3.12 / 3.13
- Windows package build + complete-tree attestation
- native Windows SCM qualification

Candidate selectors:

```yaml
linux-test:
  runs-on: [self-hosted, Linux, X64, hms-gpt-vps-linux]

windows-test:
  runs-on: [self-hosted, Windows, X64, hms-gpt-vps-windows]
```

The dependent Windows package/native-service jobs must use the same reviewed Windows self-hosted runner label if GitHub-hosted Windows is unavailable.

Custom labels route jobs; they do not authorize code. The runner must remain offline except for the exact frozen qualification attempt.

## Failure / cleanup policy

If registration fails part-way, do not rerun over the same non-empty directory. Preserve diagnostics, remove any partially registered runner using GitHub's normal runner-removal procedure if registration reached GitHub, and clean only the dedicated runner root after confirming ownership.

After qualification:

1. stop both foreground runners;
2. remove both repository registrations;
3. confirm neither runner is Online in repository Settings;
4. only then consider local runner-directory cleanup.

## Current proof boundary

Fallback infrastructure status remains `STAGED_NOT_EXECUTED` until the scripts are actually run on suitable Windows/Linux hosts and GitHub reports the runners Online/Idle.

Even after CI succeeds, project authority remains false until a real managed Hyper-V qualification artifact proves it:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`

PR #11 remains Draft / DO NOT MERGE until both the required CI execution and the later real guest proof gates are satisfied.
