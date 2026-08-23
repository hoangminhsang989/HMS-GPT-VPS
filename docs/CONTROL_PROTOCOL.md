# HMS-GPT-VPS Control Protocol

## Purpose

Define the minimum contract between the Windows VM agent, HMS Bridge/control service, and the supported ChatGPT integration.

## Non-goal

A normal pasted URL is not itself a remote shell and MUST NOT be treated as one. The URL/code only bootstraps pairing through a compatible HMS control integration.

## Actors

- **Desktop/Provisioner**: Windows host authority for Hyper-V lifecycle and elevation.
- **Guest Agent**: least-privilege service inside the Windows VM.
- **Bridge**: authenticated relay/control service reachable by outbound connection from the guest.
- **ChatGPT integration**: MCP/connector/action layer exposing scoped HMS tools.

## Device registration

On first healthy boot the agent generates a device keypair locally and registers only the public identity with the Bridge. The private key remains protected inside the guest.

Registration returns a pending device identifier. It does not grant ChatGPT control.

## Pairing

A pairing record contains at minimum:

```json
{
  "pair_id": "p_example",
  "instance_id": "hms-01",
  "expires_at": "RFC3339 timestamp",
  "single_use": true,
  "requested_scopes": [
    "workspace.read",
    "workspace.write",
    "process.test",
    "git.status"
  ]
}
```

The public pair URL/code carries only an opaque, high-entropy, short-lived bootstrap token or lookup identifier. It MUST NOT contain a VM Administrator password, host credential, reusable agent secret, API key, or refresh token.

## Redemption

1. User submits the pair link/code through the HMS ChatGPT integration.
2. Bridge validates TTL, single-use state, instance binding, and requested scopes.
3. If local approval is required, redemption enters `pending_approval`.
4. Desktop/guest presents the instance identity and requested scopes to the operator.
5. Approval completes the binding.
6. Pair token is atomically invalidated.
7. Bridge issues independently revocable session/device authorization.

Replay of the original pair token after success MUST fail.

## Session requirements

- short-lived access authorization;
- refresh/renewal separated from the pair token;
- per-instance scope binding;
- session identifier in every request;
- request identifier/idempotency key for write operations;
- explicit expiry;
- server-side revocation;
- rotation without reprovisioning the VM;
- no permanent credential returned to ChatGPT as plain text.

## Initial tool surface

Conceptual ChatGPT tools:

```text
hms.list_instances
hms.instance_status
hms.read_file
hms.write_file
hms.run_test
hms.git_status
hms.audit_events
```

A write-file call is logically equivalent to:

```json
{
  "instance_id": "hms-01",
  "path": "chatgpt-control-test.txt",
  "content": "Hello from ChatGPT",
  "idempotency_key": "req_example"
}
```

The agent resolves the relative path under `C:\HMS-Workspace`, evaluates policy, writes atomically, and returns metadata such as:

```json
{
  "ok": true,
  "path": "C:\\HMS-Workspace\\chatgpt-control-test.txt",
  "size": 18,
  "sha256": "...",
  "timestamp": "...",
  "audit_event_id": "evt_example"
}
```

## Approval classes

Normally automatable inside an authorized workspace:

- read project file;
- write/replace project file;
- run unit tests/lint/typecheck/build under configured policy;
- git status/diff/log;
- read logs and audit events.

Always approval-gated unless a future policy explicitly narrows them further:

- delete VM/VHDX;
- format disk;
- change host networking;
- writable host-folder sharing;
- host shell access;
- guest Administrator command;
- reset entire workspace;
- destructive checkpoint restore;
- credential export.

## Transport

The guest Agent establishes an outbound authenticated TLS session to the Bridge. The normal product mode requires no inbound Internet port to the guest and no LAN exposure for RDP, WinRM, SSH, or the agent API.

## Audit

Every accepted or rejected request records:

- timestamp;
- instance/session identity;
- request/action name;
- normalized target;
- policy decision;
- approval identifier when applicable;
- result/error class;
- request/audit correlation ID.

Secrets and authorization headers are never written to audit logs.
