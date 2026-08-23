# PROJECT STATE — HMS-GPT-VPS

## Current revision

R002A — Windows Hyper-V host execution foundation

## Status

IN_PROGRESS

## Authority

- Repository: `hoangminhsang989/HMS-GPT-VPS`
- Default branch: `main`
- Repository visibility: private
- GitHub is the source-of-truth for source and working documentation.

## Product authority

The canonical product is a Windows desktop tool that creates and manages an isolated Windows Hyper-V VM on the same Windows PC.

Primary workflow:

`Tạo VPS -> detect Hyper-V host readiness -> create/recover Windows Hyper-V VM -> install HMS Agent -> create isolated VM workspace -> start outbound secure control channel -> display one-time pairing link -> pair with supported ChatGPT/HMS integration -> ChatGPT creates/reads/tests files inside the VM.`

Windows is the primary guest OS. Linux/WSL2 and remote VPS backends are optional future modes.

## Delivered foundation

R001 includes fail-closed policy, workspace isolation, audit log, policy-gated executor, read-only Git operations, health CLI, tests and CI.

R002 includes the Hyper-V prerequisite model, deterministic Windows VM configuration and provisioning plan generation.

R002A now adds:

- read-only Windows/Hyper-V host probe using PowerShell;
- persistent atomic VM instance registry;
- idempotent PowerShell executor foundation that ensures a base Hyper-V VM shell;
- tests for registry round-trip/update and generated VM script shape.

## Security baseline

1. Deny by default.
2. ChatGPT does not receive direct physical-host control by default.
3. Normal agent work runs non-admin inside the VM.
4. Host drives are not automatically shared into the VM.
5. Restrict filesystem access to configured VM project roots.
6. Require explicit approval for destructive or privileged operations.
7. Audit accepted and rejected actions.
8. Do not store reusable plaintext credentials in the repository or pairing link.

## R002A remaining objectives

- Add explicit elevation gate for host mutations.
- Add Hyper-V feature enable/reboot recovery workflow.
- Add Windows installation media/base-image management.
- Add VM boot readiness detection.
- Bootstrap guest Windows automatically.
- Install HMS Agent inside the guest.

## Canonical end-to-end target

ChatGPT creates `C:\HMS-Workspace\chatgpt-control-test.txt` inside the managed Windows VM, reads it back through the paired control channel, and receives SHA-256, size, timestamp and audit event ID.
