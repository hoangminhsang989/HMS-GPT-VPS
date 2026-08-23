# Architecture — HMS-GPT-VPS

## Product goal

HMS-GPT-VPS is a Windows-hosted tool that can automatically provision an isolated Linux execution environment on the same Windows PC, install and configure the HMS VPS Agent, then expose a secure pairing link that the operator can paste into ChatGPT/HMS tooling.

The intended user flow is:

```text
Windows PC
   |
   +--> HMS-GPT-VPS desktop tool
           |
           +--> [Tạo VPS]
                  |
                  +--> provision isolated Linux guest
                  |      preferred backend: WSL2
                  |      optional backend: Hyper-V VM
                  |
                  +--> install HMS VPS Agent
                  +--> create workspace + device identity
                  +--> establish outbound secure tunnel/control channel
                  +--> generate one-time pairing link
                                 |
                                 v
                         Copy link to ChatGPT
                                 |
                                 v
                    ChatGPT / HMS control plane
                                 |
                                 v
                         HMS VPS Agent
                                 |
                 +---------------+----------------+
                 |               |                |
              Files            Tests             Git
                 |               |                |
           create/edit       run commands      status/diff
```

## Important terminology

The Linux environment created on the same Windows machine is technically a local virtualized Linux environment rather than a rented Internet VPS. The product UI may still call it `VPS` for simplicity, but internally the runtime backend must record whether the instance is WSL2, Hyper-V, or another supported virtualization backend.

## One-button provisioning

The Windows application must provide a primary action `Tạo VPS` that performs unattended provisioning as far as the host permits:

1. Check virtualization prerequisites.
2. Select the preferred supported backend.
3. Install/enable required Windows components only with explicit operator approval when elevation is required.
4. Create the Linux instance.
5. Install Python/runtime dependencies and HMS VPS Agent.
6. Create a dedicated unprivileged agent user.
7. Create the authorized project workspace.
8. Generate device identity and short-lived pairing credentials.
9. Start the agent automatically.
10. Establish an outbound secure connection so inbound router/NAT configuration is not required.
11. Display the pairing link and a `Sao chép liên kết` action.

Provisioning must be resumable and idempotent: closing/reopening the Windows tool must not corrupt an existing instance or create duplicates blindly.

## Pairing link contract

The pairing link is a bootstrap credential, not a permanent bearer secret. It must:

- be HTTPS;
- contain or resolve to a random high-entropy one-time token;
- expire quickly;
- become invalid after successful pairing;
- identify the target instance without revealing reusable host credentials;
- never expose SSH passwords, root passwords, API keys, or long-lived tokens in the URL;
- result in a bound session/device credential after pairing.

Example conceptual form only:

```text
https://<control-service>/pair/<one-time-random-token>
```

## ChatGPT control requirement

Pasting a URL into ordinary ChatGPT does not by itself grant arbitrary command execution. HMS-GPT-VPS therefore requires a compatible ChatGPT/HMS control integration (connector/action/MCP/Bridge or equivalent supported tool surface) that can authenticate the pairing link and call the agent/control API.

The product must not pretend that a normal web link alone is sufficient. The Windows UI should report pairing readiness separately from control-integration readiness.

## Control-plane design

Preferred topology:

```text
ChatGPT / HMS tooling
        |
        v
Authenticated HMS control service / connector
        |
        | HTTPS / WebSocket
        v
Outbound tunnel/session from local Linux instance
        |
        v
HMS VPS Agent
        |
        +--> Policy engine
        |      +--> identity/session checks
        |      +--> project-root scope
        |      +--> capability checks
        |      +--> destructive-action approval gate
        |
        +--> File operations
        +--> Shell/process execution
        +--> Git operations
        +--> Test/build operations
        +--> Telemetry/logging
```

The local agent should initiate the Internet-facing connection whenever possible. Directly exposing an unauthenticated local agent port to the public Internet is forbidden.

## Initial proof-of-control acceptance test

The first end-to-end milestone after pairing is intentionally small and observable:

1. Windows tool reports the instance `READY`.
2. Operator copies the pairing link into the supported ChatGPT/HMS integration.
3. ChatGPT requests creation of `workspace/chatgpt-control-test.txt`.
4. Agent policy validates the project scope and path.
5. Agent writes a deterministic test payload.
6. ChatGPT reads the file back through the same control path.
7. Agent returns SHA-256, size, timestamp, and audit event ID.
8. Operator can see the file directly inside the Linux workspace.

No destructive or privileged capability is required for this milestone.

## Core modules

- `provisioner`: Windows-side WSL2/Hyper-V detection, installation and instance lifecycle.
- `instance_registry`: stable IDs, backend type, state and recovery metadata.
- `pairing`: one-time pairing token and device/session binding.
- `transport`: authenticated outbound control channel.
- `agent`: process lifecycle and request dispatch.
- `policy`: authorization, scope and destructive-action decisions.
- `workspace`: project-root validation and safe path resolution.
- `executor`: controlled command execution.
- `audit`: structured audit records.
- `health`: host, guest and agent readiness diagnostics.

## Trust boundaries

1. A pasted pairing URL is untrusted until validated by the pairing service.
2. ChatGPT/HMS control plane is not implicitly trusted for arbitrary host access.
3. Every requested operation passes through local agent policy.
4. Windows host files are not exposed by default; only explicitly mounted/project-bound roots are accessible.
5. The Linux agent runs without root by default.
6. Elevation, destructive operations and host-level changes require explicit policy and operator approval.
7. Project boundaries are authoritative; path traversal and symlink escapes fail closed.
8. Every accepted or rejected control request is auditable.

## Runtime backend priority

### Preferred: WSL2

Use WSL2 first when available because it provides lightweight Linux virtualization, fast provisioning and strong Windows integration. The tool must still prevent accidental access to arbitrary Windows-mounted files.

### Optional: Hyper-V

Use Hyper-V when stronger VM separation is desired and the Windows edition/hardware supports it. Hyper-V support must not be a prerequisite for the first working release.

## Remote rented VPS

A future mode may provision or connect to an actual remote VPS. That is separate from the primary local-Windows one-button workflow and must reuse the same agent, pairing, policy and audit contracts.
