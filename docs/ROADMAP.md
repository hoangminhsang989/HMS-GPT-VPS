# Roadmap — HMS-GPT-VPS

## Product workflow authority

Primary product workflow:

`Windows tool -> Tạo VPS -> local isolated Linux instance -> auto-install HMS VPS Agent -> generate one-time pairing link -> paste link into supported ChatGPT/HMS control integration -> create/read/test files directly in the Linux workspace.`

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

## Stage 1 — Windows One-Button Provisioner

- Windows desktop application shell.
- Primary `Tạo VPS` action.
- Virtualization prerequisite detection.
- WSL2 backend as first implementation.
- Optional Hyper-V backend abstraction.
- Elevation flow only when Windows features/install require it.
- Idempotent/resumable provisioning state machine.
- Linux image/distribution installation.
- Dedicated unprivileged HMS agent account.
- Instance registry and lifecycle: create/start/stop/recover/remove-with-confirmation.
- Workspace creation without exposing arbitrary Windows drives.

### Stage 1 gate

A clean supported Windows machine can create a Linux instance from the UI and reopen the tool without duplicating or corrupting it.

## Stage 2 — Agent Bootstrap & Pairing

- Automatic HMS VPS Agent installation inside the guest.
- Device identity generation.
- One-time high-entropy pairing token.
- Short pairing-link expiration.
- Single-use token invalidation.
- Outbound authenticated tunnel/control session.
- No router port-forward requirement.
- Separate UI states for instance readiness, agent readiness and pairing readiness.
- Copy-link action.

### Stage 2 gate

Tool displays a valid short-lived pairing link for a healthy instance without exposing reusable host credentials.

## Stage 3 — ChatGPT/HMS Control Integration

- Compatible connector/action/MCP/Bridge control surface.
- Pair-link redemption and device binding.
- Session identity and expiration.
- Replay protection.
- Request/response correlation and idempotency.
- Capability negotiation.
- Explicit project binding.
- Request audit IDs.

### Stage 3 gate

Pasting/redeeming the link in the supported ChatGPT/HMS integration binds exactly one agent instance and creates an authenticated control session.

## Stage 4 — First End-to-End File Proof

- `file.create` within authorized workspace.
- `file.read` within authorized workspace.
- `file.write`/replace with atomic semantics.
- SHA-256 and metadata response.
- Policy enforcement before every filesystem operation.
- Audit accepted and rejected operations.

### Canonical acceptance test

ChatGPT creates `workspace/chatgpt-control-test.txt`, reads it back, and receives matching SHA-256/size/timestamp/audit event ID. The operator can observe the same file directly in the Linux instance.

## Stage 5 — Development Capabilities

- Safe subprocess execution.
- Test/lint/typecheck/build commands.
- Git status/diff/log.
- Controlled Git branch/commit/push policy.
- Process management.
- Runtime logs.
- CPU/RAM/disk/process telemetry.

## Stage 6 — Deployment & Operations

- systemd service integration.
- Service status/start/restart under policy.
- Docker integration under scoped permissions.
- Deployment workflows with rollback checkpoints.
- Backup/restore primitives.
- Health monitoring.

## Stage 7 — Multi-Instance / HMS Integration

- Multiple local or remote VPS instances.
- Project affinity.
- Isolated concurrent work.
- Presence/heartbeat.
- Explicit handoff/fallback semantics.
- Vietnamese operator UI and status.
- Remote rented VPS mode using the same agent/pairing contract.

## Stage 8 — Production Hardening

- Threat-model review.
- Security regression suite.
- Pairing/session abuse tests.
- Failure/recovery testing.
- Credential rotation.
- Tunnel reconnection and offline recovery.
- Windows reboot recovery.
- Guest corruption recovery.
- Soak testing and production release gate.
