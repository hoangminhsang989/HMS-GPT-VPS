# R002F — Durable per-request MCP ingress provenance

Status: `STAGED_NOT_EXECUTED`

This tranche stages a non-secret durable provenance authority for principal-bound Agent dispatches created inside the protected MCP ingress context. It binds one external MCP request to the ingress generation that existed when the request first acquired its atomic dispatch/idempotency authority, without storing the ingress capability token.

## Why a separate provenance table

The existing `principal_agent_dispatch_claims` schema remains unchanged. Provenance is stored in a separate `principal_dispatch_ingress_provenance` table in the exact same hardened `control-idempotency.sqlite3` authority. This avoids changing the established dispatch-row ABI while still allowing the NEW transaction to atomically bind all three authorities.

The provenance row contains only non-secret identity/digest data: schema version, principal SHA-256, pair id, session id and epoch, instance id, request id, request SHA-256, command SHA-256, and the 32-lowercase-hex MCP ingress generation. It never stores the raw OAuth bearer, pairing/session token, Agent credential, tunnel API key, or MCP tunnel ingress capability token.

## Atomic NEW authority

`IngressProvenancePrincipalDispatchIntentStore` extends the existing principal-dispatch store. For a NEW request it uses the same `BEGIN IMMEDIATE` transaction to insert:

1. the ordinary idempotency `CLAIMED` row;
2. the exact `principal_agent_dispatch_claims` row; and
3. when the request is executing inside a capability-authenticated `/mcp` context, the exact ingress-provenance row.

Any exception before `COMMIT`, including provenance construction or insertion failure, rolls back all three. A provenance row cannot be appended later to make an older direct dispatch appear MCP-originated.

## Retry / replay rules

The current request context is read from `current_mcp_tunnel_ingress_generation()`.

For an already-existing dispatch:

- no stored provenance + no current MCP generation: ordinary direct-path resume/replay remains available;
- no stored provenance + current MCP generation: fail closed as ambiguous; a direct dispatch cannot be laundered into MCP-proven authority;
- stored provenance + no current MCP generation: fail closed as ambiguous; an MCP-proven dispatch cannot resume through an unprotected path;
- stored provenance + a current MCP generation: exact intent/provenance identity is required, while the immutable original generation is never rewritten.

A legitimate retry after an HMSBridge/tunnel restart may therefore resume through a later protected generation while preserving the generation that created the original NEW authority. The later composite qualification must compare the challenged request's stored generation with independently qualified native tunnel-generation evidence; a retry alone cannot satisfy that comparison.

## Exact schema authority

Initialization verifies the provenance table's exact columns, SQLite types, NOT NULL flags, composite primary-key order, absence of defaults, and `WITHOUT ROWID` storage. A pre-existing same-name table with schema drift is rejected rather than silently adopted.

Provenance parsing reuses the production dispatch validators for principal/request digests, pair/session/request identifiers, and the broader canonical `instance_id` contract. The generation itself must be exactly 32 lowercase hexadecimal characters.

## Production wiring

The canonical `assemble_production_bridge()` authority itself now constructs `IngressProvenancePrincipalDispatchIntentStore` over the exact production `IdempotencyStore`. The existing `BridgeProductionAssembly.dispatch_intent_store` type remains the parent `PrincipalDispatchIntentStore`, so downstream APIs do not gain a parallel ABI.

The same provenance-aware store is passed to the existing `PrincipalAgentControlService`, and the existing MCP server is built from that exact control object. There is no wrapper-only production path and no second dispatch store in the production assembly.

A direct/non-gated call can still create an ordinary dispatch, but such a NEW claim has no provenance row. A later protected retry cannot add missing provenance, so direct calls cannot become MCP-proven evidence after the fact.

## Deliberate proof boundary

This tranche stages durable provenance creation but does not yet teach the external durable observer to require/read it and does not yet compare it against independently observed native tunnel generation.

Therefore these remain false until the next observer/composite tranche:

- `mcp_adapter_invocation_proven`
- `openai_control_plane_origin_proven`
- `full_bridge_command_flow_proven`

Even after request-specific protected MCP ingress is proven, `openai_control_plane_origin_proven` must remain false until separate live ChatGPT/OpenAI connector evidence exists.

## Validation while staging

Candidate production source and tests compile successfully. Focused dependency-isolated regressions cover atomic MCP NEW provenance persistence, direct NEW with no provenance, direct-to-MCP laundering rejection, MCP-proven-to-direct resume rejection, later-generation protected retry with immutable original provenance, rollback on provenance insertion failure, tampered digest rejection, schema-drift rejection, and canonical production-assembly use of the provenance-aware store.

Repository pytest: NOT RUN in this environment. GitHub CI: NOT CLAIMED. Real Windows / Hyper-V / SCM / LocalMachine-DPAPI / OpenAI tunnel / ChatGPT connector execution: NOT RUN.
