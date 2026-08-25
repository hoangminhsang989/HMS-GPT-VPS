# R002F Principal-Bound Agent Control Façade

Status: **STAGED_NOT_EXECUTED**

Branch: `r002f-pairing-readiness-runtime`

## Purpose

This tranche connects the already principal-bound control session to the
existing outbound Bridge -> Agent command transport without executing workspace
or process actions on the physical Bridge host.

The intended model-facing sequence is now representable as:

`pair_vps(link) -> write_file(...) / read_file(...) -> signed durable Agent queue -> outbound managed guest Agent -> guest policy runtime -> result`

No raw pairing token, control-session token or Agent device credential is
returned by the façade.

## Atomic dispatch ownership

Agent dispatch ownership and idempotency must be one authority decision. A prior
revision staged a create-only filesystem intent before the idempotency claim.
Independent committed-byte review rejected that design: if a foreign unresolved
claim already existed, the first façade call would fail ambiguous but leave the
new intent behind; a later retry could then mistake that older intent for proof
that the foreign claim belonged to Agent dispatch. A crash after intent creation
but before claim creation had the same ambiguity.

The corrected design uses `PrincipalDispatchIntentStore` as an atomic SQLite
claim binder over the **exact same hardened IdempotencyStore database** used by
ControlGateway. Its `BEGIN IMMEDIATE` transaction is authoritative:

- if no idempotency record exists, it inserts both the ordinary `CLAIMED` row
  and the exact `principal_agent_dispatch_claims` row, then commits once;
- if an unresolved idempotency row exists, resume is allowed only when the exact
  dispatch-binding row already exists and matches all authority fields;
- if a claim exists without a dispatch-binding row, it is permanently ambiguous
  for this façade and no binding row is created retroactively;
- completed replay also requires the exact dispatch binding before a cached
  receipt may be considered.

Therefore there is no durable state in which this façade has published dispatch
ownership without the corresponding idempotency claim, or vice versa.

## Dispatch binding contents

The atomic dispatch-binding row contains only:

- schema version;
- principal SHA-256;
- pair_id;
- exact session_id and session epoch;
- instance_id and request_id;
- canonical control request SHA-256;
- exact full Agent command SHA-256;
- session expiry.

It does not contain request parameters, file content, raw principal subject,
pairing/session tokens or Agent credentials.

## Control ordering

A control call uses the following authority order:

1. load the encrypted principal/session binding;
2. authorize exact instance/action scope against ControlSessionStore;
3. require fresh authenticated pairing readiness for the same pair_id;
4. build one exact AgentCommandEnvelope whose deadline is the bound session
   expiry and whose destructive approval field is null;
5. atomically create/resume/replay the idempotency + Agent-dispatch binding;
6. re-observe fresh pairing readiness;
7. read the Agent queue for the exact command, or enqueue it if absent;
8. if pending, leave the atomic idempotency claim unresolved and return pending;
9. if completed, verify the exact Agent result and complete idempotency with a
   small digest receipt;
10. on later replay, verify that receipt against the exact completed Agent queue
    result before returning model-visible data.

The Bridge never invokes ControlActionRuntime in this path. The guest
AgentPolicyCommandExecutor remains the execution/policy boundary.

## Crash recovery

- crash before the atomic transaction commits: neither idempotency nor dispatch
  ownership exists, so retry may begin normally;
- crash after atomic claim commit but before enqueue: both exact authorities
  exist, so retry resumes the same Agent command;
- crash after enqueue: the exact queue request-id/command binding and Agent-side
  idempotency journal preserve side-effect identity;
- foreign/direct-path claim: no dispatch binding exists and repeated calls remain
  ambiguous forever unless an explicit reconciliation process resolves it;
- crash after Agent completion but before idempotency completion: retry loads the
  exact completed Agent result and finalizes the same digest receipt;
- crash after idempotency completion but before response delivery: replay verifies
  the receipt against the exact completed Agent result.

## Exact queue read

`agent_command_exact_status.py` is a read-only package-internal adapter over
AgentCommandStore's hardened connection and row validators. It compares the
exact stored Agent command body to the requested AgentCommandEnvelope and never
creates, expires, completes or otherwise mutates a queue row.

This avoids using `enqueue_command()` merely as a read/verification primitive.

## Replay privacy

The idempotency database does not cache the full Agent result for this façade.
Instead the completed idempotency response is a small receipt containing:

- receipt schema/kind;
- instance_id/request_id;
- exact command SHA-256;
- exact Agent result SHA-256.

On replay the façade loads the completed result from AgentCommandStore and
verifies both digests before returning it. Therefore a `workspace.read` result
may return file content to the authenticated caller without copying that content
into either `idempotency_records.response_json` or the dispatch-binding table.

AgentCommandStore still necessarily contains the durable Agent result required
for reliable delivery/replay.

## Destructive operations

This tranche deliberately does not invent an approval mechanism.

`workspace.write` with `mode=replace` is rejected at the Bridge façade before an
atomic dispatch claim is created. The command therefore cannot become pollable
without a future explicit approval flow that binds approval to the exact command
SHA-256.

`write_file()` exposes create-only semantics. Existing guest policy still
applies all path/workspace restrictions. `read_file()` maps only to
`workspace.read`.

## Fresh Agent requirement

A new/resumed dispatch requires PairingReadinessRuntime to prove fresh Agent
presence, `pairing_ready=true`, `paired=true`, and the exact bound pair_id both
before the atomic claim and immediately before enqueue.

If freshness is lost after an atomic claim, no command is enqueued; the exact
claim+dispatch binding permits a later safe retry after Agent health recovers.

## Staged regression

`tests/test_r002f_principal_agent_control.py` covers:

- pending submission and exact retry without duplicate command creation;
- atomic creation of one idempotency row plus one dispatch-binding row;
- durable Agent completion followed by idempotency finalization and replay;
- digest-only replay receipt that excludes returned file content;
- simulated crash after atomic claim commit but before enqueue, then safe resume;
- a foreign unresolved claim remaining ambiguous across repeated façade calls,
  with zero dispatch-binding rows and zero Agent commands;
- stale Agent rejection before idempotency/dispatch mutation;
- replace-mode rejection before idempotency/dispatch/queue mutation.

These are source/regression artifacts only until an actual project test runner
executes them.

## Evidence boundary

This tranche does **not** claim:

- a deployed MCP/OpenAI app endpoint;
- public HTTPS/TLS reachability;
- a real ChatGPT authenticated principal;
- a real managed Hyper-V Agent poll/result cycle;
- actual file creation in a managed guest;
- production pairing readiness.

Project proof boundaries remain false:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`

PR #11 remains outside this branch and remains **DO NOT MERGE** until its own CI,
proof-authority and real Hyper-V qualification gates are satisfied.
