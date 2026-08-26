# R002F — External MCP command-flow durable observer

Status: `STAGED_NOT_EXECUTED`

This tranche stages a strict read-only observer for one externally coordinated `read_file` qualification challenge. It does **not** create a pairing link, submit an MCP request, enqueue an Agent command, start/stop HMSBridge, or claim that OpenAI/ChatGPT originated the request. Its purpose is to prove the durable principal/session/dispatch/Agent chain without manufacturing the command being qualified.

## Why the observer is separate

The OpenAI Secure MCP Tunnel is control-plane driven: the tunnel runtime forwards MCP commands selected through the configured tunnel authority to the local MCP server. HMS therefore does not invent a public `https://<tunnel-id>` endpoint and does not use a direct HTTP client as a substitute for the real ChatGPT/OpenAI control-plane path.

The live composite runner will later bracket an actual user/ChatGPT invocation with HMSBridge PID, tunnel PID/generation, Agent generation, and final Stopped/Manual proof. This observer supplies only the durable host-side evidence needed by that runner.

## Challenge contract

`ExternalMcpReadChallenge` is non-secret and contains:

- schema version;
- challenge id;
- exact source commit;
- instance id;
- random request id;
- canonical relative forward-slash workspace path;
- expected file-content SHA-256;
- issued/expires timestamps.

The challenge lifetime is bounded to 15 minutes. Qualification paths reject absolute paths, backslashes, drive/stream colons, control characters, empty segments, `.` and `..`.

## Read-only authority chain

The observer opens SQLite databases with `mode=ro`, `PRAGMA query_only=ON`, and a bounded read transaction. It pins the lexical regular-file identity before/open/during/after observation and rejects symlink/junction/reparse redirects.

For one exact `(instance_id, request_id)` it requires:

1. Exactly one `principal_agent_dispatch_claims` row.
2. The matching `idempotency_records` row to be `completed`, with the exact request SHA-256 and integrity-checked completion receipt.
3. The exact consumed, non-revoked `pairing_records` record with `workspace.read` scope.
4. The exact active `control_sessions` record with matching instance/session/epoch and `workspace.read` scope.
5. The LocalMachine-DPAPI `PrincipalSessionBinding` loaded from the pinned `secrets/principal-bindings` authority, matching principal SHA-256, pair id, session/family ids, token SHA-256, scopes, timestamps, epoch and dispatch expiry.
6. The exact completed `agent_commands` row, validated by the production Agent command-store validator.
7. The signed Agent command to have exact action `workspace.read`, exact challenge path, no destructive approval digest, and deadline equal to the bound session expiry.
8. The principal dispatch command SHA-256 to equal the canonical full `AgentCommandEnvelope.to_dict()` hash used by `PrincipalAgentControlService`.
9. The Agent result to be `outcome=ok` with exact `workspace.read` response fields.
10. Returned bytes to match response size, response SHA-256, and challenge expected SHA-256. UTF-8 and canonical base64 results are both supported.
11. The idempotency completion receipt to bind the exact command SHA-256 and exact result SHA-256.
12. Pairing/session/binding authority to be re-observed at the end; any rotation/revocation/drift fails closed.

The observer also reconstructs the exact production `ControlRequest` using the observed session id plus challenge request/action/path and requires its `request_sha256()` to equal the durable dispatch intent. This prevents a matching request id from proving a different action or path.

## Deliberately false proof flags

A successful observer result keeps all of these false:

- `mcp_adapter_invocation_proven`
- `openai_control_plane_origin_proven`
- `secure_tunnel_generation_proven`
- `full_bridge_command_flow_proven`

A durable database chain alone cannot prove where the initiating authenticated principal call came from. Those flags may only advance in a later composite runner that brackets an actual ChatGPT/OpenAI tunnel invocation.

## Validation performed while staging

- Candidate observer `py_compile`: PASS.
- Candidate repository test `py_compile`: PASS.
- Synthetic dependency-harness regression: **9/9 PASS**.
- Covered: exact success/read-only behavior, challenge path/lifetime rejection, duplicate dispatch, incomplete idempotency, binding/session drift, Agent action drift, completion-receipt digest drift, content SHA drift, and binding re-observation drift.
- Repository pytest: NOT RUN in this environment.
- Real Windows / Hyper-V / LocalMachine-DPAPI / OpenAI tunnel / ChatGPT connector execution: NOT RUN.

Therefore this tranche remains `STAGED_NOT_EXECUTED` and does not change `full_bridge_command_flow_proven=false`.
