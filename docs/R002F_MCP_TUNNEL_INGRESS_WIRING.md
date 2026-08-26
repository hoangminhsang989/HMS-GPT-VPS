# R002F MCP Tunnel Ingress Wiring

Status: `STAGED_NOT_EXECUTED`

This tranche wires the previously staged `McpTunnelIngressGate` contract into the production HMSBridge service generation and the pinned OpenAI tunnel-client child environment.

## Generation authority

For each HMSBridge service start:

1. the service proves its runtime identity;
2. if SCM stop was already requested, startup returns without generating an ingress capability or opening listeners;
3. exactly one 32-byte random capability is generated as 64 lowercase hexadecimal characters;
4. Agent TLS starts;
5. the local MCP ASGI app is wrapped by `McpTunnelIngressGate` using that capability;
6. the MCP server starts on exact `127.0.0.1:8765` and exact `/mcp`;
7. the same capability is passed in-memory to `SecureMcpTunnelRuntimeConfig` with `repr=False`;
8. the secure tunnel runtime adds the capability to its already-scrubbed child environment through OpenAI `tunnel-client v0.0.12` `MCP_EXTRA_HEADERS` env indirection;
9. tunnel readiness must still pass before HMSBridge can report ready.

No durable Bridge runtime schema field is added for this secret. The existing schema-v2 durable `tunnel_id` remains non-secret and unchanged.

## Child environment

The existing child environment remains allowlist-based. The ingress wiring adds only:

- `HMS_TUNNEL_INGRESS_TOKEN=<per-start capability>`
- `MCP_EXTRA_HEADERS=X-HMS-Tunnel-Ingress: env:HMS_TUNNEL_INGRESS_TOKEN`

The plaintext capability is not added to argv or to `MCP_EXTRA_HEADERS`. The tunnel runtime clears its mutable child-environment copies of both `CONTROL_PLANE_API_KEY` and `HMS_TUNNEL_INGRESS_TOKEN` after the spawn/start attempt. Python immutable strings are not zeroizable; this is reference/surface minimization rather than a memory-erasure claim.

## Local MCP authority

Only exact `/mcp` is capability-gated. OAuth discovery/protected-resource routes remain passed to the existing MCP auth stack.

A direct local request to `/mcp`, even if it carries a separately valid OAuth bearer, cannot reach MCP tool dispatch without the per-start ingress capability.

The gate returns a generic `404 not found` for missing, wrong, duplicate, malformed, or non-ASCII capability values. The response does not echo the expected or supplied token.

## Upstream pin

This wiring relies on exact OpenAI `tunnel-client v0.0.12` source authority at commit:

`881c9a8fed7cccbe6607cd419863bbca506b8215`

The relevant upstream contract is that `MCP_EXTRA_HEADERS` supports `env:VAR` value indirection and the MCP client injects configured extra headers on requests to the configured MCP server origin/path.

Aggregate upstream control-plane metrics such as `commands_polled` remain insufficient by themselves for per-HMS-request provenance and are not treated as such.

## Regression proof staged here

Dependency-isolated local regression covers:

- standalone ingress contract behavior;
- tunnel runtime startup/readiness/shutdown behavior;
- capability absent from tunnel argv and runtime-config repr;
- exact child env indirection and token delivery;
- API key and ingress token mutable-env scrub on spawn failure;
- service startup still ordered TLS -> MCP -> tunnel;
- service shutdown still orders tunnel before TLS, with MCP shutdown retained between those ingress layers;
- one generated capability is delivered unchanged to both MCP and tunnel factories;
- default MCP factory wraps the exact streamable-HTTP app in `McpTunnelIngressGate` while preserving loopback, port, stateless JSON response, access-log-off, and lifespan settings;
- pre-stopped runtime still opens no listener and does not generate a capability.

## Provenance meaning after native execution

This wiring removes the previously identified local-loopback ambiguity for an exact HMS MCP tool invocation: a direct local caller does not possess the per-start capability by default, while the exact pinned tunnel child receives it through the service-owned child environment.

However, `openai_control_plane_origin_proven` and `full_bridge_command_flow_proven` remain false until a live qualification brackets all of the following in one service generation:

- exact reviewed HMSBridge service PID/identity;
- exact pinned tunnel child PID, parent PID, executable path and SHA-256;
- live tunnel readiness;
- exact externally supplied random HMS `request_id` observed durably through MCP -> Bridge -> Agent;
- successful external ChatGPT/OpenAI connector invocation rather than a local test caller;
- stable service/tunnel generation before and after the command;
- final service stop and listener teardown.

A local Administrator can inspect or tamper with processes and is outside this per-process capability boundary. This mechanism is not an anti-admin security boundary.

## Proof boundary

No real Windows service or tunnel child was started by this tranche. No real OpenAI control-plane command or ChatGPT connector attachment was executed. No production pairing readiness is claimed.

Project state therefore remains `STAGED_NOT_EXECUTED`.
