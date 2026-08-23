# PROJECT STATE — HMS-GPT-VPS

## Current revision

R002 — Windows Hyper-V provisioning foundation

## Status

IN_PROGRESS

## Authority

- Repository: `hoangminhsang989/HMS-GPT-VPS`
- Default branch: `main`
- Repository visibility: private
- GitHub is the source-of-truth for source and working documentation.

## Product authority

The canonical product is a **Windows desktop tool** that creates and manages an isolated **Windows Hyper-V VM on the same Windows PC**.

Primary workflow:

`Tạo VPS -> create/recover Windows Hyper-V VM -> install HMS Agent -> create isolated VM workspace -> start outbound secure control channel -> display one-time pairing link -> pair with supported ChatGPT/HMS integration -> ChatGPT creates/reads/tests files inside the VM.`

Windows is the primary guest OS. Linux/WSL2 and remote VPS backends are optional future modes.

## Current implementation

R001 foundation already includes:

- fail-closed policy primitive;
- workspace isolation resolver;
- append-only audit log;
- policy-gated command executor;
- read-only Git operations;
- health CLI;
- unit tests and GitHub Actions CI definition.

R002 begins the Windows host/Hyper-V provisioning layer.

## Security baseline

1. Deny by default.
2. ChatGPT does not receive direct physical-host control by default.
3. Normal agent work runs non-admin inside the VM.
4. Host drives are not automatically shared into the VM.
5. Restrict filesystem access to configured VM project roots.
6. Require explicit approval for destructive or privileged operations.
7. Audit accepted and rejected actions.
8. Do not store reusable plaintext credentials in the repository or pairing link.

## R002 objectives

- Model Hyper-V host prerequisites.
- Model deterministic VM configuration.
- Add provisioning phases/state machine.
- Generate safe PowerShell provisioning commands/plans.
- Keep planning separate from host mutation.
- Add tests for defaults and validation.
- Then implement actual Windows host execution with explicit elevation gates.

## Canonical end-to-end target

ChatGPT creates `C:\HMS-Workspace\chatgpt-control-test.txt` inside the managed Windows VM, reads it back through the paired control channel, and receives SHA-256, size, timestamp and audit event ID.
