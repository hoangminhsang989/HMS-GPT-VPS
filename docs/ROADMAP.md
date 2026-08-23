# Roadmap — HMS-GPT-VPS

## Stage 0 — Foundation

- Repository authority and project state.
- Architecture and security baseline.
- Python package scaffold.
- Fail-closed policy primitives.
- Health/diagnostic CLI.
- Initial unit tests.

## Stage 1 — Local VPS Agent

- Authorized project registry.
- Safe path resolver.
- Controlled subprocess executor.
- Git status/diff/log operations.
- Structured audit log.
- systemd service packaging.

## Stage 2 — Secure Remote Control

- Authenticated encrypted control channel.
- Session identity and expiration.
- Replay protection.
- Capability negotiation.
- Request/response correlation and idempotency.

## Stage 3 — Deployment & Operations

- Service status/start/restart under policy.
- Docker integration under scoped permissions.
- Deployment workflows with rollback checkpoints.
- CPU/RAM/disk/process telemetry.
- Log retrieval and health checks.

## Stage 4 — HMS Bridge Integration

- Bind VPS agents to HMS projects.
- Multi-VPS registry and presence.
- Project affinity and isolated concurrent work.
- Explicit handoff/fallback semantics.
- Operator UI and Vietnamese user-facing status.

## Stage 5 — Production Hardening

- Threat-model review.
- Security regression suite.
- Failure/recovery testing.
- Credential rotation.
- Backup/restore and disaster recovery.
- Soak testing and production release gate.
