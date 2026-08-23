# PROJECT STATE — HMS-GPT-VPS

## Current revision

R002B — Windows Hyper-V enable/reboot/image/readiness foundation

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

`Tạo VPS -> detect Hyper-V host readiness -> request elevation only when required -> enable Hyper-V after explicit operator approval -> persist resume state if reboot is required -> create/recover Windows Hyper-V VM -> validate Windows installation image -> boot VM -> install HMS Agent -> create isolated VM workspace -> start outbound secure control channel -> display one-time pairing link -> pair with supported ChatGPT/HMS integration -> ChatGPT creates/reads/tests files inside the VM.`

Windows is the primary guest OS. Linux/WSL2 and remote VPS backends are optional future modes.

## Delivered foundation

R001 includes fail-closed policy, workspace isolation, audit log, policy-gated executor, read-only Git operations, health CLI, tests and CI.

R002 includes the Hyper-V prerequisite model, deterministic Windows VM configuration and provisioning plan generation.

R002A adds read-only host probing, persistent atomic VM registry and idempotent Hyper-V VM shell execution.

R002B now adds:

- explicit elevation decision gate;
- approval-gated Hyper-V feature enablement;
- persistent reboot/resume state store;
- Windows ISO file and optional SHA-256 validation;
- Hyper-V VM running/heartbeat readiness probe;
- tests covering elevation, resume persistence and image validation.

## Security baseline

1. Deny by default.
2. ChatGPT does not receive direct physical-host control by default.
3. Normal agent work runs non-admin inside the VM.
4. Host drives are not automatically shared into the VM.
5. Restrict filesystem access to configured VM project roots.
6. Require explicit approval for destructive or privileged operations.
7. Host elevation is never implied by a normal provision request.
8. Audit accepted and rejected actions.
9. Do not store reusable plaintext credentials in the repository or pairing link.

## R002B remaining objectives

- Wire elevation through a Windows desktop/operator confirmation flow.
- Register automatic post-reboot resume safely.
- Add Windows image acquisition/import strategy without embedding licenses or credentials.
- Create/install the guest OS rather than only the VM shell.
- Bootstrap guest Windows automatically.
- Install HMS Agent inside the guest.

## Canonical end-to-end target

ChatGPT creates `C:\HMS-Workspace\chatgpt-control-test.txt` inside the managed Windows VM, reads it back through the paired control channel, and receives SHA-256, size, timestamp and audit event ID.
