# R002F — HMSBridge protected pairing-link IPC

Status: `STAGED_NOT_EXECUTED`

This tranche closes the production authority gap between
`PairingReadinessRuntime.issue()` and the host UI/tool that must display the
one-time link a user can copy into ChatGPT.

## Security boundary

The raw pairing token remains owned by the running `NT SERVICE\HMSBridge`
process and by the existing current-user DPAPI pairing-link lease. This tranche
does **not** convert that lease to LocalMachine DPAPI and does not add a
host-readable plaintext/token file.

The only host retrieval surface is the fixed local Windows named pipe:

`\\.\pipe\HMS-GPT-VPS-Pairing`

The server is created with:

- `FILE_FLAG_FIRST_PIPE_INSTANCE`;
- message mode;
- nonblocking `PIPE_NOWAIT`;
- `PIPE_REJECT_REMOTE_CLIENTS`;
- a protected DACL containing only:
  - `SYSTEM` — Full Control;
  - `BUILTIN\Administrators` — read/write;
  - the exact `NT SERVICE\HMSBridge` service SID — Full Control.

No TCP listener, configurable pipe name, PID option, runtime-config option, or
secret option is introduced.

## Host anti-spoof gate

`hms-bridge pairing-link` accepts no arguments.

Before connecting, the host client proves that it is an elevated Administrator
and that the exact `HMSBridge` service is:

- account `NT SERVICE\HMSBridge`;
- start mode `Manual`;
- state `Running`;
- backed by one positive SCM process ID;
- bound to a canonical service SID.

After the pipe is opened, `GetNamedPipeServerProcessId` must equal that SCM PID.
The SCM evidence is read again after the response and the PID/service SID must
remain unchanged. A pre-created or substituted pipe therefore fails closed even
if its DACL otherwise allows the caller.

## Protocol

The request is one bounded UTF-8 JSON object with the exact fields:

- `schema_version = 1`;
- `operation = "issue_pairing_link"`;
- a fresh nonce.

Duplicate keys, unknown fields, malformed nonces, oversized messages, invalid
UTF-8, or unsupported operations are connection-scoped rejects and do not
mutate pairing state.

For a valid request, HMSBridge calls the production
`PairingReadinessRuntime.issue()` authority. Existing readiness rules therefore
remain authoritative: provisioning state and fresh authenticated Agent presence
must be valid before a link can be issued or recovered.

Success returns only the exact pair ID, expiry, and one-time HTTPS pairing link.
The link is validated to contain the same pair ID and exactly one non-empty
`#token=` fragment. Runtime exceptions are reduced to the bounded
`pairing_unavailable` response; exception text and secrets are never serialized.

## SCM lifecycle integration

The existing production TLS/MCP runtime is not rewritten. A small
`BridgePairingSurfaceRuntime` wrapper is installed by the service entrypoint:

1. start the reviewed inner TLS/MCP runtime;
2. start and prove the named-pipe pairing surface;
3. only then return success to the SCM host, allowing `SERVICE_RUNNING`;
4. a fatal pipe failure signals the same SCM stop event and becomes a runtime
   failure;
5. shutdown closes the pipe first and still closes MCP/TLS if pipe shutdown
   fails.

This preserves the existing SCM readiness and cleanup authority while making
pairing-link availability part of service readiness.

## Validation boundary

The tranche includes cross-platform protocol/lifecycle regression tests and
syntax compilation. Native Windows named-pipe ACL, PID-binding, DPAPI lease
recovery, real `HMSBridge` process identity, and end-to-end link issuance remain
external live qualification requirements.

Until those native proofs pass:

- `pairing_link_ipc_live_proven = false`;
- `full_bridge_command_flow_proven = false`;
- `bootstrap_retired = false`;
- `pairing_ready = false`;
- `automatic_start_enabled = false`.
