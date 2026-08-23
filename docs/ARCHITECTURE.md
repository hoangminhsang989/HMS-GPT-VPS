# Architecture — HMS-GPT-VPS

## Product goal

HMS-GPT-VPS is a Windows-hosted tool that automatically provisions an isolated **Windows virtual machine** on the same Windows PC, installs and configures the HMS Agent inside that VM, then exposes a secure one-time pairing link that the operator can paste into a supported ChatGPT/HMS control integration.

The Windows VM is the primary execution target. Linux, WSL2, or remote rented VPS backends may be added later, but they are not the default product path.

## Canonical user flow

```text
Windows host PC
   |
   +--> HMS-GPT-VPS desktop tool
           |
           +--> [Tạo VPS]
                  |
                  +--> check Hyper-V + virtualization prerequisites
                  +--> create isolated Windows VM
                  +--> install/configure HMS Agent in VM
                  +--> create dedicated workspace in VM
                  +--> start agent automatically
                  +--> establish outbound authenticated control channel
                  +--> generate one-time pairing link
                                 |
                                 v
                         Copy link to ChatGPT
                                 |
                                 v
                    Supported ChatGPT/HMS integration
                                 |
                                 v
                          HMS Agent in VM
                                 |
                 +---------------+----------------+
                 |               |                |
              Files          PowerShell          Git/Test
```

## Why Windows VM is primary

The project is intended to support Windows-native development and automation workloads. A Windows VM allows the isolated agent environment to use PowerShell, Git for Windows, Python, Codex CLI, Windows applications, UI Automation, and other Windows-only tooling without granting ChatGPT direct control of the physical host by default.

## Virtualization backend

### Primary: Hyper-V Windows VM

Hyper-V is the canonical backend for the first full implementation. The provisioner must detect:

- Windows edition and Hyper-V availability;
- CPU virtualization support;
- whether required Hyper-V components are enabled;
- available RAM and disk space;
- existence and health of an already-managed HMS VM.

If elevation or a Windows restart is required, the tool must explain the reason and obtain explicit operator approval before changing host features.

### Future/optional backends

- Windows Sandbox for disposable short-lived test environments.
- WSL2/Linux for Linux-specific workloads.
- Remote rented VPS using the same agent/pairing contract.

These are secondary modes and must not change the Windows-first default.

## One-button provisioning

The Windows application exposes a primary action `Tạo VPS`. The intended state machine is:

1. `PREFLIGHT` — verify Windows/Hyper-V prerequisites.
2. `HOST_READY` — enable prerequisites only after approval when needed.
3. `IMAGE_READY` — validate the configured Windows base image/template.
4. `VM_CREATING` — create VM, virtual disk, CPU/RAM and network configuration.
5. `VM_BOOTING` — start the VM and wait for guest readiness.
6. `GUEST_BOOTSTRAP` — install/configure HMS Agent and development prerequisites.
7. `AGENT_READY` — agent health and workspace checks pass.
8. `PAIRING_READY` — create a short-lived one-time pairing link.
9. `CONTROL_READY` — supported ChatGPT/HMS integration has paired successfully.

Provisioning must be resumable and idempotent. Reopening the Windows tool must discover and recover a managed VM instead of blindly creating duplicates.

## Host/guest isolation

The physical Windows host and managed Windows VM are separate trust zones.

By default:

- the agent has no arbitrary host filesystem access;
- host drives are not automatically shared into the VM;
- clipboard, enhanced session, shared folders and device passthrough are disabled unless explicitly enabled by policy;
- the VM workspace is authoritative for ChatGPT-created/test files;
- destructive host operations are outside the default agent capability set.

## Pairing link contract

The displayed link is a bootstrap credential, not a permanent bearer secret. It must:

- use HTTPS;
- contain or resolve to a high-entropy one-time token;
- expire quickly;
- become invalid after successful pairing;
- identify exactly one managed VM/agent instance;
- never expose Windows passwords, administrator credentials, API keys or reusable host secrets;
- result in a bound device/session credential after redemption.

Conceptual form only:

```text
https://<control-service>/pair/<one-time-token>
```

A normal pasted web URL alone cannot magically give ChatGPT arbitrary machine-control capability. The URL must be consumed by a compatible ChatGPT/HMS connector/action/MCP/Bridge or equivalent supported integration that can authenticate and call the control API.

## Control-plane topology

```text
ChatGPT / HMS tooling
        |
        v
Authenticated HMS control integration
        |
        v
HMS control service
        |
        | HTTPS / WebSocket
        v
Outbound session from Windows VM
        |
        v
HMS Agent
        |
        +--> Policy engine
        +--> Workspace isolation
        +--> File operations
        +--> PowerShell/process executor
        +--> Git operations
        +--> Test/build operations
        +--> Audit + telemetry
```

The VM agent should establish outbound connectivity whenever possible so the user does not need router port forwarding and the physical Windows host does not expose a public command port.

## First end-to-end acceptance test

1. User clicks `Tạo VPS`.
2. Tool reports managed Windows VM `READY`.
3. Tool displays a one-time pairing link.
4. User pastes/redeems the link in the supported ChatGPT/HMS integration.
5. ChatGPT requests creation of `C:\\HMS-Workspace\\chatgpt-control-test.txt` inside the VM.
6. Agent validates project scope and writes a deterministic payload.
7. ChatGPT reads the file back through the same control path.
8. Agent returns SHA-256, size, timestamp and audit event ID.
9. User can open the VM and see the exact same file.

No destructive or administrator capability is required for this milestone.

## Core modules

- `windows_host`: host prerequisite and Hyper-V capability detection.
- `provisioner`: Hyper-V Windows VM creation/recovery state machine.
- `instance_registry`: stable VM IDs and lifecycle metadata.
- `guest_bootstrap`: agent/runtime installation inside the Windows VM.
- `pairing`: one-time pairing and device/session binding.
- `transport`: authenticated outbound control channel.
- `agent`: request dispatch and lifecycle.
- `policy`: capability, scope and destructive-action decisions.
- `workspace`: VM workspace validation and safe path resolution.
- `executor`: controlled PowerShell/process execution.
- `audit`: structured audit records.
- `health`: host, VM and agent diagnostics.

## Security baseline

1. Deny capabilities by default.
2. Do not grant ChatGPT direct host control by default.
3. Do not run normal agent work as Windows Administrator by default.
4. Restrict filesystem operations to configured VM project roots.
5. Require explicit approval for destructive or privileged operations.
6. Keep reusable credentials out of pairing URLs and the Git repository.
7. Audit accepted and rejected operations.
8. Treat VM-to-host sharing as an explicit privileged capability.
