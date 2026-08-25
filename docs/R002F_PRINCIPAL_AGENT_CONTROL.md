# R002F Principal-Bound Agent Control Façade

Status: **STAGED_NOT_EXECUTED**

Branch: `r002f-pairing-readiness-runtime`
Parent authority when staged: `798cf930c9b3cbd13d925452b3e1d96e79db22dc`

## Purpose

This tranche connects the already principal-bound control session to the
existing outbound Bridge -> Agent command transport without executing workspace
or process actions on the physical Bridge host.

The intended model-facing sequence is now representable as:

`pair_vps(link) -> write_file(...) / read_file(...) -> signed durable Agent queue -> outbound managed guest Agent -> guest policy runtime -> result`

No raw pairing token, control-session token or Agent device credential is
returned by the façade.

## Dispatch ordering

A control call uses the following authority order:

1. load the encrypted principal/session binding;
2. authorize exact instance/action scope against ControlSessionStore;
3. require fresh authenticated pairing readiness for the same pair_id;
4. build one exact AgentCommandEnvelope whose deadline is the bound session
   expiry and whose destructive approval field is null;
5. publish an immutable digest-only PrincipalDispatchIntent;
6. claim the existing ControlGateway idempotency key;
7. re-observe fresh pairing readiness;
8. read the Agent queue for the exact command, or enqueue it if absent;
9. if pending, leave idempotency CLAIMED and return pending;
10. if completed, verify the exact Agent result and complete idempotency with a
    small digest receipt;
11. on later replay, verify that receipt against the exact completed Agent queue
    result before returning model-visible data.

The Bridge never invokes ControlActionRuntime in this path. The guest
AgentPolicyCommandExecutor remains the execution/policy boundary.

## Crash recovery rule

The immutable dispatch intent is deliberately published before the idempotency
claim and contains no request parameters or content. It binds:

- principal SHA-256;
- pair_id;
- exact session_id and epoch;
- instance_id and request_id;
- canonical control request SHA-256;
- exact full Agent command SHA-256;
- session expiry.

This ordering distinguishes two cases after a Bridge crash:

- **older intent + unresolved claim**: the request was already assigned to the
  Agent-dispatch path, so the exact command may be safely reconciled/enqueued;
- **new intent + older unresolved claim**: the claim may belong to another
  execution path, so the façade fails closed as ambiguous and does not enqueue.

A crash after the intent but before the claim is also safe: retry finds the
older exact intent, creates the claim, then proceeds. A crash after enqueue is
safe because AgentCommandStore and the guest idempotency journal bind request_id
to the exact command/result authority.

## Exact queue read

`agent_command_exact_status.py` adds a read-only package-internal adapter over
AgentCommandStore's already hardened connection and row validators. It compares
the exact stored Agent command body to the requested AgentCommandEnvelope and
never creates, expires, completes or otherwise mutates a queue row.

This avoids using `enqueue_command()` merely as a read/verification primitive.

## Replay privacy

The idempotency database does not cache the full Agent result for this façade.
Instead it stores only a small receipt containing:

- receipt schema/kind;
- instance_id/request_id;
- exact command SHA-256;
- exact Agent result SHA-256.

On replay the façade loads the completed result from AgentCommandStore and
verifies both digests before returning it. Therefore a `workspace.read` result
may return file content to the authenticated caller without duplicating that
content into IdempotencyStore.

AgentCommandStore still necessarily contains the durable Agent result needed for
reliable delivery/replay.

## Destructive operations

This tranche deliberately does not invent an approval mechanism.

`workspace.write` with `mode=replace` is rejected at the Bridge façade before a
dispatch intent is published. The command therefore cannot become pollable
without a future explicit approval flow that binds approval to the exact command
SHA-256.

`write_file()` exposes create-only semantics. Existing guest policy still
applies all path/workspace restrictions. `read_file()` maps only to
`workspace.read`.

## Fresh Agent requirement

A new/resumed dispatch requires PairingReadinessRuntime to prove fresh
Agent presence, `pairing_ready=true`, `paired=true`, and the exact bound pair_id
both before intent publication and immediately before enqueue.

If freshness is lost after an idempotency claim, no command is enqueued; the
older exact intent permits a later safe retry after Agent health recovers.

## Staged regression

`tests/test_r002f_principal_agent_control.py` covers:

- pending submission and exact retry without duplicate command creation;
- durable Agent completion followed by idempotency finalization and replay;
- digest-only replay receipt that excludes returned file content;
- simulated crash after idempotency claim but before enqueue, then safe resume;
- unresolved claim that predates the dispatch intent failing closed with no
  Agent command;
- stale Agent rejection before intent or idempotency mutation;
- replace-mode rejection before intent/queue mutation.

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
