# R002E Self-Hosted Runner Removal

Status: staged on branch `r002e-self-hosted-runner-fallback`; not executed.

This lifecycle closeout is intentionally separate from runner installation and does not delete runner directories.

GitHub's official self-hosted runner removal flow uses a fresh, time-limited remove token with:

- Windows: `config.cmd remove --token TOKEN`
- Linux: `./config.sh remove --token TOKEN`

The official removal command removes the runner from GitHub and removes its local runner configuration files. Merely stopping a foreground runner leaves the registration Offline and does not immediately remove it.

## Security policy

- Stop the foreground runner before deregistration.
- Obtain a fresh repository runner **remove token** from GitHub Settings → Actions → Runners → runner → Remove.
- Never reuse the earlier registration token as a removal token.
- Never put a remove token in a repository file, issue, reusable document, or persistent `.env` file.
- The HMS removal wrappers read the token only from process environment variable `HMS_GITHUB_RUNNER_REMOVE_TOKEN`, unset it before invoking the official config tool, and clear their in-process variable afterward.
- The wrappers call only the official runner `config remove` command.
- The wrappers do **not** delete the runner install directory or arbitrary files.
- Filesystem cleanup remains a separate explicit action after deregistration and authority verification.

## Windows removal

After the elevated foreground runner console is stopped:

```powershell
$env:HMS_GITHUB_RUNNER_REMOVE_TOKEN = '<fresh remove token>'
.\scripts\remove_self_hosted_runner.ps1
```

The wrapper:

- requires elevated Windows PowerShell;
- rejects reparse redirects in the fixed runner path;
- refuses removal while the exact HMS `Runner.Listener.exe` is still running;
- requires `.runner`, `.credentials`, and `config.cmd` before invoking removal;
- requires `.runner` and `.credentials` to be absent after official removal;
- preserves `C:\ProgramData\HMS-GPT-VPS\GitHubRunner`.

Expected output includes:

```text
deregistered = True
local_root_preserved = True
filesystem_cleanup_performed = False
```

## Linux removal

After the foreground Linux runner is stopped:

```bash
export HMS_GITHUB_RUNNER_REMOVE_TOKEN='<fresh remove token>'
bash scripts/remove_self_hosted_runner_linux.sh
```

The wrapper:

- runs only on Linux as non-root;
- rejects symlink redirects in HOME/runner state;
- requires `.runner`, `.credentials`, and `config.sh`;
- calls official `config.sh remove --token`;
- requires `.runner` and `.credentials` to be absent afterward;
- preserves `~/.local/share/hms-gpt-vps/github-runner-linux`.

Expected output includes:

```text
deregistered=True
local_root_preserved=True
filesystem_cleanup_performed=False
```

## Post-removal gate

After each removal:

1. confirm GitHub no longer reports that runner Online/Offline under repository Settings → Actions → Runners;
2. confirm no self-hosted CI job remains queued for the removed labels;
3. preserve local runner files until diagnostics are no longer needed;
4. only perform filesystem cleanup under a separate explicit cleanup decision.

Runner removal does not change the R002E proof boundary. `hyperv_guest_proven`, `full_bridge_command_flow_proven`, `bootstrap_retired`, and `pairing_ready` remain false until separately proven.
