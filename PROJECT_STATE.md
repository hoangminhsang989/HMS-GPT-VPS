# PROJECT STATE — HMS-GPT-VPS

## Stage

Stage 0 — Foundation/bootstrap

## Status

IN_PROGRESS

## Authority

- Repository: `hoangminhsang989/HMS-GPT-VPS`
- Default branch: `main`
- Repository visibility: private
- GitHub is the source-of-truth for project source and working documentation.

## Current objective

Build a secure VPS agent that can receive authorized work from ChatGPT/HMS tooling and expose controlled capabilities for files, shell commands, Git, services, deployment, and telemetry.

## Security baseline

1. Deny by default.
2. Do not run the application as root by default.
3. Restrict filesystem access to configured project roots.
4. Restrict privileged commands using explicit policy.
5. Require explicit user approval for destructive operations.
6. Record an audit trail for command execution and privileged actions.
7. Do not store plaintext long-lived credentials in the repository.

## Stage 0 exit criteria

- Architecture documented.
- Security policy documented.
- Roadmap documented.
- Python package scaffold created.
- Policy model scaffold created.
- Basic health endpoint/CLI skeleton implemented.
- Unit tests for security defaults pass.

## Next revision

R001 — Agent foundation and fail-closed policy skeleton.
