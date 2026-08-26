# R002F — External MCP command-flow composite runner

Status: `STAGED_NOT_EXECUTED`

This tranche stages the first composite runner that can bracket one **externally issued** principal-bound `read_file` request with a single live HMSBridge process, Secure MCP Tunnel child generation, and authenticated HMSAgent generation. The runner deliberately does not call MCP itself and does not enqueue an Agent command itself.

## Qualification input

The Windows Administrator runner receives only non-secret challenge authority on argv:

- exact 40-character lowercase Git source commit;
- canonical relative workspace path;
- expected workspace content SHA-256;
- create-only challenge JSON path;
- create-only final proof JSON path;
- bounded external wait timeout (30–900 seconds).

Managed-guest bootstrap username/password remain environment-only and are consumed from `HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME` / `HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD`. They are never accepted as CLI fallbacks.

## Ordered live proof

The qualification requires, in order:

1. Protected Bridge runtime config and immutable Bridge package authority validate.
2. HMSBridge is exact `Stopped/Manual` before activation.
3. The managed HMSAgent is already Running/Automatic and its health boot/process identity is observed.
4. HMSBridge starts through the existing reviewed activation path.
5. The exact tunnel child is independently qualified, including parent PID, immutable executable/hash, exact loopback health listener and approved `/readyz` class.
6. A fresh authenticated Agent hello and later heartbeat are observed for one exact device/boot/connection epoch.
7. The Agent process/boot is re-observed unchanged.
8. A fresh non-secret challenge is generated and published create-only. Its MCP tool is exactly `read_file`; arguments are exact `instance_id`, random `request_id`, and canonical path. The file also carries source commit, expected content SHA-256 and bounded issued/expiry timestamps.
9. The runner only **observes** the existing principal dispatch/idempotency database read-only. No dispatch row means “not arrived yet”; one exact atomically bound `claimed` row means “in progress”; only `completed` advances to the full durable observer. Duplicate dispatch rows, a dispatch without its atomic idempotency row, malformed authority or unsupported state fail closed immediately.
10. The existing durable observer then proves the exact principal/session/binding/idempotency/Agent-command/result/content-SHA chain for the challenge request id.
11. Challenge identity returned by the observer must match all exact challenge fields.
12. Agent presence, Agent process/boot, and the independently qualified tunnel generation are re-observed unchanged after the external read.
13. HMSBridge is stopped in `finally`; post-state must again be exact `Stopped/Manual`, with reviewed listeners absent.

A challenge file is intentionally retained on failure/timeout as non-secret forensic coordination evidence. The runner never deletes it and never mutates the guest workspace.

## Proof boundary

A successful staged result may set:

- `authenticated_principal_control_path_proven=true`
- `durable_external_principal_read_proven=true`
- `secure_tunnel_generation_proven=true`
- stable HMSBridge/tunnel/Agent generation booleans true
- `runner_invoked_mcp=false`
- `runner_enqueued_agent_command=false`

It must still keep all of these false:

- `mcp_adapter_invocation_proven`
- `openai_control_plane_origin_proven`
- `full_bridge_command_flow_proven`
- `bootstrap_retired`
- `pairing_ready`
- `automatic_start_enabled`

The ephemeral MCP tunnel-ingress capability prevents an ordinary loopback caller with only an OAuth bearer from reaching `/mcp`, and the composite runner proves a live reviewed tunnel generation remained present across the external request. However, the current durable request records do not carry a per-request ingress provenance marker. Therefore this tranche does **not** claim that a specific completed request originated in the OpenAI control plane or that the MCP adapter itself is independently proven from durable bytes. Those require a later live connector/origin evidence tranche (or a separately reviewed per-request ingress provenance design).

## Staging validation

- Candidate source + CLI `py_compile -Werror`: PASS.
- Dependency-isolated composite/runner regression: PASS.
- Existing durable observer remains a separate previously staged proof layer.
- Full repository pytest: not claimed from this environment unless a complete repository harness is available.
- Real Windows / Hyper-V / LocalMachine-DPAPI / OpenAI tunnel / ChatGPT connector execution: **NOT RUN**.

Therefore this tranche remains `STAGED_NOT_EXECUTED`.
