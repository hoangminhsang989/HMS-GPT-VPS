# PROJECT STATE — HMS-GPT-VPS

## Current revision

R002C — Provisioning state machine and control-contract foundation (Tranche 1)

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

`Tạo VPS -> detect Hyper-V host readiness -> request elevation only when required -> enable Hyper-V after explicit operator approval -> persist/resume after reboot if required -> verify Windows image -> ensure isolated Hyper-V network -> create/recover Windows VM -> unattended Windows install -> PowerShell Direct guest bootstrap -> install least-privilege HMS Agent -> create isolated VM workspace -> start outbound secure control channel -> generate one-time pairing link/code -> pair through supported ChatGPT/HMS integration -> ChatGPT creates/reads/tests files inside the VM.`

Windows is the primary guest OS. Linux/WSL2 and remote VPS backends remain optional future modes.

## Delivered foundation

R001:

- fail-closed policy;
- workspace isolation;
- append-only audit log;
- policy-gated executor;
- read-only Git operations;
- health CLI;
- unit tests and CI.

R002/R002A/R002B:

- Hyper-V prerequisite/configuration model;
- host probe;
- instance registry;
- idempotent VM shell executor;
- explicit elevation gate;
- Hyper-V enable flow;
- reboot/resume store;
- Windows ISO/SHA-256 validation;
- VM running/heartbeat readiness probe.

R002C Tranche 1 now adds:

- persistent `ProvisionState` model and atomic state store;
- reconcile-oriented `ProvisioningOrchestrator`;
- structured PowerShell runner foundation;
- generated secret-free Windows unattend answer-file foundation;
- R002C state-machine/unattend tests;
- `docs/R002C_ARCHITECTURE.md`;
- `docs/CONTROL_PROTOCOL.md` defining the real ChatGPT pairing/control contract.

## Architecture decisions locked by deep research

1. **Hyper-V Windows VM is the production default** because it provides the appropriate isolation boundary for remote AI-controlled code/file execution.
2. **Host and guest control planes are separate.** ChatGPT/HMS control targets the guest agent only; Hyper-V and host Administrator operations remain local desktop authority.
3. **Provisioning is reconcile-oriented and persistent**, not a one-shot PowerShell script.
4. **Internal vSwitch + NAT** is preferred over an external bridged switch for the managed guest.
5. **PowerShell Direct** is the preferred local guest-bootstrap transport after Windows is installed; normal mode does not expose WinRM/RDP/SSH to LAN/Internet.
6. **A pasted URL alone does not give ChatGPT shell access.** The pair link/code is only a one-time bootstrap credential for a compatible HMS MCP/connector/Bridge control integration.
7. Pairing credentials must be short-lived, high entropy, single-use and contain no reusable VM/agent/host secret.
8. Windows unattended installation is the MVP image strategy; generalized Sysprep VHDX may become the fast path later.

## Security baseline

1. Deny by default.
2. ChatGPT has no default path to the physical Windows host.
3. Normal HMS Agent work runs without Administrator rights inside the VM.
4. Host drives are not automatically shared into the VM.
5. Filesystem access is restricted to configured VM workspace roots.
6. Destructive or privileged operations require explicit approval.
7. Host elevation is never implied by a normal provision/control request.
8. Agent/Bridge control is outbound-authenticated; no public inbound guest management port is required.
9. Reusable plaintext credentials must not appear in Git, pairing links, or audit logs.
10. Pairing/session authorization is per-instance, scoped, expiring, revocable and independently rotatable.

## R002C remaining objectives

### Tranche 2 — Hyper-V reconciliation

- ensure dedicated Internal vSwitch;
- ensure NAT configuration;
- reconcile VM by stable observed identity/VMId;
- attach verified ISO/DVD;
- configure Gen2 boot order/Secure Boot intentionally;
- start VM and persist observed state;
- postcondition checks after every mutation.

### Tranche 3 — Windows guest installation

- finish unattended Windows Setup media pipeline;
- safely supply bootstrap-only guest credential without storing reusable secret in Git;
- wait through install/reboot cycles;
- detect final guest heartbeat/PowerShell Direct readiness;
- optional prepared generalized VHDX optimization later.

### Tranche 4 — Guest bootstrap and Agent service

- create `C:\HMS-Workspace` and NTFS ACLs;
- install HMS Agent as a Windows Service using least privilege/service SID strategy;
- protect local device/session secrets with Windows-native secret storage + ACLs;
- add `/healthz`/capability readiness;
- add privileged broker boundary for rare Administrator-only guest actions.

### Tranche 5 — Pairing/control proof

- implement one-time pairing record/token lifecycle;
- outbound authenticated Agent ↔ Bridge session;
- compatible ChatGPT MCP/connector/action surface;
- `workspace.read`, `workspace.write`, `process.test`, `git.status`, `audit.read`;
- session expiration/rotation/revocation and idempotency keys;
- canonical end-to-end file proof.

## Canonical end-to-end target

ChatGPT, through the supported HMS control integration, creates `C:\HMS-Workspace\chatgpt-control-test.txt` inside the managed Windows VM, reads it back through the same authenticated control path, and receives matching SHA-256, byte size, timestamp and audit event ID — without requiring host filesystem sharing or host Administrator control.
