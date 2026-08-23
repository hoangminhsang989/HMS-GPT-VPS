# R002C Architecture — Reconcile-Oriented Windows Provisioning

## Scope

R002C connects the R001/R002/R002A/R002B primitives into a persistent Windows Hyper-V provisioning state machine. The Windows host remains the provisioning authority. ChatGPT/HMS control remains confined to the Windows guest agent.

## Required trust boundary

```text
ChatGPT / HMS integration
        |
        v
HMS Bridge / MCP control plane
        |
        v
HMS Agent inside Windows VM
        |
        v
C:\HMS-Workspace

        X no default path
        |
        v
Windows host Administrator / Hyper-V
```

The host control plane and guest control plane MUST remain separate.

## Provisioning model

Provisioning is a reconcile loop, not a one-shot script. Every state transition is persisted before the next externally mutating step is requested.

Canonical states:

```text
IDLE
  -> PREFLIGHT
  -> NEED_ELEVATION (only when required)
  -> REBOOT_PENDING (only when required)
  -> IMAGE_READY
  -> NETWORK_READY
  -> VM_CREATED
  -> INSTALL_MEDIA_READY
  -> OS_INSTALLING
  -> GUEST_BOOTED
  -> GUEST_BOOTSTRAP
  -> AGENT_INSTALLING
  -> AGENT_HEALTHY
  -> PAIRING_PENDING
  -> READY
```

Any unrecoverable precondition failure enters `FAILED` with an operator-visible reason.

## Hyper-V network

The preferred production topology is a dedicated Hyper-V Internal vSwitch plus host NAT. The guest receives outbound Internet access without being bridged directly onto the physical LAN. Normal mode exposes no RDP, WinRM, SSH, or HMS Agent management port to the LAN or Internet.

## Windows installation

MVP installation uses verified Windows ISO media plus generated `Autounattend.xml`/`unattend.xml` material. The repository MUST NOT contain Windows product keys, guest Administrator passwords, reusable API keys, pairing secrets, or other long-lived credentials.

A future optimization may use a generalized Sysprep VHDX base image after the ISO-based flow is stable and independently verified.

## Guest bootstrap

Bootstrap order:

1. Hyper-V VM reports running.
2. Hyper-V Heartbeat reports healthy.
3. PowerShell Direct becomes available from the local Hyper-V host.
4. HMS bootstrap payload is transferred without requiring inbound network management.
5. Workspace and service identity are created.
6. HMS Agent is installed as a Windows Service using least privilege.
7. Agent health is verified.
8. Only then may the pairing subsystem create a short-lived one-time pairing record.

WinRM/OpenSSH are fallback/integration options, not the default bootstrap path.

## Pairing and ChatGPT control

A copied URL alone does not grant ChatGPT arbitrary HTTP or shell execution. HMS-GPT-VPS requires an HMS control integration such as a supported MCP/connector/Bridge surface. The displayed link/code is a bootstrap credential for that integration.

Pairing requirements:

- high entropy;
- single use;
- short TTL;
- bound to one `instance_id`;
- requested capability scopes recorded explicitly;
- no VM password or permanent agent secret in the URL;
- local/operator approval may be required before final binding;
- successful redemption invalidates the bootstrap token;
- resulting session credentials are independently revocable and rotatable.

## Initial control capabilities

The first end-to-end capability set is intentionally small:

- `workspace.stat`
- `workspace.read`
- `workspace.write`
- `process.test`
- `git.status`
- `audit.read`

Host Hyper-V operations are not part of this tool surface.

## Acceptance proof

R002C ultimately targets this observable proof:

1. tool provisions/reconciles a Windows VM;
2. agent becomes healthy;
3. pairing becomes ready;
4. supported ChatGPT/HMS integration binds to the instance;
5. ChatGPT creates `C:\HMS-Workspace\chatgpt-control-test.txt`;
6. ChatGPT reads it back;
7. response includes SHA-256, byte size, timestamp, and audit event ID;
8. no host filesystem share or host Administrator capability was needed.
