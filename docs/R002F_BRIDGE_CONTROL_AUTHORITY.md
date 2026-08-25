# R002F Bridge Control Authority Stores

Status: **STAGED_NOT_EXECUTED**

Branch: `r002f-pairing-readiness-runtime`

## Purpose

Before a ChatGPT app/MCP-facing control facade can enqueue commands for a managed
guest, the two Bridge-side durable replay/queue databases must be treated as
security authority rather than ordinary SQLite convenience storage.

This correction hardens:

- `AgentCommandStore`, which owns signed Bridge-to-Agent command identity,
  pending/completed/expired state and returned Agent results;
- `IdempotencyStore`, which owns authenticated control-request replay authority.

It does not add a public listener, an MCP server, a principal-binding credential,
or a new remote capability.

## Agent command queue authority

The command store now preserves the existing rule that its parent security
directory must already exist. It additionally requires:

- lexical database paths only; no `resolve()`-based authority rebinding;
- rejection of symlink/junction/reparse traversal;
- create-once main database publication when absent;
- exact regular-file identity pinned at startup and rechecked on each operation;
- finite bounded SQLite timeout configuration;
- connection cleanup even if PRAGMA/setup fails;
- explicit schema version validation;
- exact stored state, hash, timestamp and JSON types;
- canonical lowercase SHA-256 text;
- bounded strict JSON with duplicate-key rejection;
- consistency between SQL `(instance_id, request_id)` authority and the signed
  command/result payloads;
- malformed persisted command states to fail closed rather than silently falling
  outside pending-count/poll queries.

Pending command expiry is also checked when a result arrives. A result received
after the durable command deadline cannot become COMPLETED merely because no
poll happened to mark that command EXPIRED first.

## Idempotency authority

The direct `ControlGateway` semantics are intentionally unchanged:

- a new exact request becomes `CLAIMED`;
- an unresolved `CLAIMED` retry is still blocked;
- the same completed request replays its exact cached response;
- changed request/result authority conflicts.

Storage hardening adds:

- lexical/stable SQLite main-file identity;
- symlink/junction/reparse rejection before and after parent creation;
- bounded finite timeout authority;
- guaranteed connection cleanup during setup failure;
- exact schema/state/hash/timestamp types;
- canonical lowercase request/response SHA-256;
- bounded strict cached-response JSON with duplicate-key rejection;
- exact `CLAIMED` versus `COMPLETED` row consistency.

No resume behavior is added to `claim()`. A future durable Agent-dispatch facade
may add a separate, explicitly-scoped resume primitive only after the queue and
principal-binding crash semantics are reviewed.

## Control topology preserved

This correction does not route app/MCP actions through host-local
`ControlActionRuntime`.

The permanent path remains:

`supported ChatGPT/HMS integration -> Bridge auth/dispatch -> signed durable Agent queue -> outbound guest Agent poll -> guest Agent policy/action runtime -> result -> Bridge`

Therefore no workspace/process side effect is moved onto the physical Windows
host by this revision.

## Evidence boundary

Regression coverage is staged for authority-path substitution, symlink/reparse
redirects, PRAGMA cleanup, noncanonical hashes, duplicate stored JSON,
malformed/non-finite timing authority, unresolved idempotency semantics, and
post-deadline Agent results.

No GitHub Actions runner, real Bridge deployment, real managed Hyper-V guest,
or ChatGPT app/MCP invocation is claimed by this source revision.

Project proof boundaries remain false until separately qualified:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`
