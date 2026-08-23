# Architecture — HMS-GPT-VPS

## Goal

Provide a controlled, auditable execution layer between ChatGPT/HMS tooling and an authorized VPS.

## Logical flow

```text
ChatGPT / HMS tooling
        |
        v
Authenticated control channel
        |
        v
HMS VPS Agent
        |
        +--> Policy engine
        |      +--> identity/session checks
        |      +--> project-root scope
        |      +--> command capability checks
        |      +--> destructive-action approval gate
        |
        +--> File operations
        +--> Shell/process execution
        +--> Git operations
        +--> Service/deployment operations
        +--> Telemetry/logging
```

## Initial modules

- `agent`: process lifecycle and request dispatch.
- `policy`: authorization, scope and destructive-action decisions.
- `workspace`: project-root validation and safe path resolution.
- `executor`: controlled command execution.
- `audit`: structured audit records.
- `health`: agent readiness and diagnostics.

## Transport

The transport is intentionally not frozen in Stage 0. Candidate production transports include mutually authenticated HTTPS or WebSocket. The implementation must not expose an unauthenticated command endpoint.

## Trust boundaries

1. ChatGPT/HMS control plane is not implicitly trusted for arbitrary host access.
2. Every requested operation passes through local VPS policy.
3. The operating-system account running the agent has least privilege.
4. Root/sudo access is separately constrained and auditable.
5. Project boundaries are authoritative; path traversal and symlink escapes must fail closed.

## Deployment target

Linux VPS is the initial target, with systemd service integration planned after the policy and execution primitives are verified.
