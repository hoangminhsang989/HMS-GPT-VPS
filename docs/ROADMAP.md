# Roadmap — HMS-GPT-VPS

## Product workflow authority

Primary workflow:

`Windows tool -> Tạo VPS -> local isolated Windows Hyper-V VM -> auto-install HMS Agent -> generate one-time pairing link -> paste/redeem link in supported ChatGPT/HMS integration -> create/read/test files directly inside the Windows VM workspace.`

Linux/WSL2 and remote rented VPS support are optional later backends, not the default product path.

## Stage 0 — Foundation

- Repository authority and project state.
- Architecture and security baseline.
- Python package scaffold.
- Fail-closed policy primitives.
- Workspace isolation resolver.
- Audit log.
- Policy-gated executor.
- Read-only Git operations.
- Health/diagnostic CLI.
- Unit tests and CI.

## Stage 1 — Windows Hyper-V Provisioner

- Windows desktop application shell.
- Primary `Tạo VPS` action.
- Windows edition/virtualization prerequisite detection.
- Hyper-V feature state detection.
- Explicit elevation/restart flow when required.
- Configurable Windows base image/template.
- VM CPU/RAM/disk/network configuration model.
- Idempotent/resumable provisioning state machine.
- Managed instance registry.
- VM create/start/stop/recover lifecycle.
- No automatic host-drive sharing.

### Stage 1 gate

A supported Windows host can preflight Hyper-V and produce a deterministic VM provisioning plan without mutating the host unexpectedly.

## Stage 2 — Windows Guest Bootstrap

- Boot managed Windows VM.
- Provision dedicated non-admin HMS agent account.
- Install Python/runtime dependencies.
- Install HMS Agent.
- Install Git and optional development prerequisites through explicit profiles.
- Create `C:\HMS-Workspace` or configured isolated workspace.
- Automatic agent startup inside VM.
- Guest health and recovery checks.

### Stage 2 gate

The managed Windows VM boots and the HMS Agent reports healthy from inside the guest without requiring ChatGPT to control the physical host.

## Stage 3 — Pairing & Secure Control Channel

- Device identity generation.
- One-time high-entropy pairing token.
- Short pairing-link expiration.
- Single-use redemption.
- Outbound authenticated control channel from VM.
- No router port-forward requirement.
- Replay protection and session expiration.
- Separate UI states for VM readiness, agent readiness, pairing readiness and control readiness.
- `Sao chép liên kết` action.

### Stage 3 gate

Tool displays a valid short-lived pairing link for exactly one healthy VM without exposing reusable Windows credentials.

## Stage 4 — ChatGPT/HMS Integration

- Compatible connector/action/MCP/Bridge control surface.
- Pair-link redemption and device binding.
- Capability negotiation.
- Explicit project binding.
- Request/response correlation and idempotency.
- Audit event IDs.

### Stage 4 gate

Pasting/redeeming the link in the supported ChatGPT/HMS integration binds exactly one Windows VM agent and creates an authenticated session.

## Stage 5 — First End-to-End File Proof

- `file.create` within authorized VM workspace.
- `file.read` within authorized VM workspace.
- Atomic file replace/write semantics.
- SHA-256 and metadata response.
- Policy check before every filesystem operation.
- Audit accepted and rejected operations.

### Canonical acceptance test

ChatGPT creates `C:\HMS-Workspace\chatgpt-control-test.txt`, reads it back, and receives matching SHA-256/size/timestamp/audit event ID. The operator can see the same file directly inside the Windows VM.

## Stage 6 — Windows Development Capabilities

- Controlled PowerShell execution.
- Python/test/lint/typecheck/build commands.
- Git status/diff/log.
- Controlled branch/commit/push policy.
- Process management.
- Windows service management under policy.
- Runtime logs.
- CPU/RAM/disk/process telemetry.
- Optional Codex CLI integration in the VM.

## Stage 7 — Windows Automation Expansion

- Windows UI Automation/accessibility.
- Window/process discovery.
- Clipboard only when explicitly enabled.
- Screenshot/vision support under policy.
- Optional application automation profiles.
- Explicit host/guest transfer workflow rather than implicit drive exposure.

## Stage 8 — Multi-Instance & Alternative Backends

- Multiple Windows VM instances.
- Project affinity and isolated concurrent work.
- Presence/heartbeat.
- Explicit handoff/fallback semantics.
- Windows Sandbox disposable mode.
- Optional WSL2/Linux mode.
- Remote rented VPS mode using the same agent/pairing contract.

## Stage 9 — Production Hardening

- Threat-model review.
- Hyper-V isolation regression suite.
- Pairing/session abuse tests.
- Failure/recovery testing.
- Credential rotation.
- Tunnel reconnection and offline recovery.
- Windows host reboot recovery.
- VM corruption/restore workflow.
- Soak testing and production release gate.
