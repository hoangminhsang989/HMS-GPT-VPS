# R002F MCP Tunnel Ingress Capability

Status: `STAGED_NOT_EXECUTED`

## Purpose

This tranche defines a fail-closed, per-service-start capability boundary for the local HMS MCP endpoint. Its purpose is to distinguish requests forwarded by the pinned OpenAI `tunnel-client` child from arbitrary direct loopback callers that merely possess an otherwise valid OAuth bearer.

This tranche stages the independent contract only. It does **not** yet wire the capability into HMSBridge production startup, the OpenAI tunnel child environment, or the external command-flow qualification runner.

## Upstream authority

The design is pinned to OpenAI `tunnel-client` `v0.0.12` at commit:

`881c9a8fed7cccbe6607cd419863bbca506b8215`

Relevant exact upstream source behavior:

- `pkg/mcpclient/internal/static_headers.go` injects configured extra headers only for the configured MCP server origin/path.
- `pkg/runtimeconfig/config.go` accepts `MCP_EXTRA_HEADERS` and resolves header values through `env:VAR` indirection.
- `pkg/runtimeconfig/http_headers.go` validates/resolves those indirections.
- `pkg/controlplane/internal/metrics.go` exposes aggregate `commands_polled`, but aggregate metrics are not sufficient to bind a specific HMS `request_id` to control-plane origin.

Therefore this contract does not rely on timestamps or aggregate telemetry for per-command provenance.

## Fixed contract

Header name:

`X-HMS-Tunnel-Ingress`

Child token environment variable:

`HMS_TUNNEL_INGRESS_TOKEN`

OpenAI runtime header configuration environment variable:

`MCP_EXTRA_HEADERS`

Header indirection value:

`X-HMS-Tunnel-Ingress: env:HMS_TUNNEL_INGRESS_TOKEN`

The capability token is exactly 32 random bytes represented as 64 lowercase hexadecimal characters.

The plaintext token itself must not be placed in argv, durable HMS runtime configuration, pairing material, logs, or the `MCP_EXTRA_HEADERS` value. The value is intended to exist only in HMSBridge process memory and the pinned child-process environment for one service generation.

## ASGI ingress gate

`McpTunnelIngressGate` gates only exact HTTP path `/mcp`.

For `/mcp` it requires:

1. exactly one case-insensitive `X-HMS-Tunnel-Ingress` header;
2. an ASCII value matching the exact 64-lowercase-hex token shape;
3. constant-time equality with the expected per-start token.

Missing, duplicate, malformed, or wrong capability values fail closed with a generic `404 not found` response and are not dispatched to the MCP OAuth or tool layer.

Non-`/mcp` routes are passed through. This intentionally preserves OAuth protected-resource / discovery endpoints, which must remain independently governed by the existing MCP authentication contract.

## Child environment construction

`build_mcp_tunnel_ingress_child_environment(...)` adds only:

- `HMS_TUNNEL_INGRESS_TOKEN=<per-start token>`
- `MCP_EXTRA_HEADERS=X-HMS-Tunnel-Ingress: env:HMS_TUNNEL_INGRESS_TOKEN`

It rejects a base environment that already contains either authority key, including case-insensitive aliases. This prevents inherited or caller-supplied override of the provenance boundary.

## Proof boundary

The staged unit proof establishes only the contract behavior:

- canonical token generation/validation;
- secret-free header indirection;
- conflict rejection in child-environment augmentation;
- fail-closed `/mcp` handling for missing/wrong/duplicate/malformed capability;
- successful downstream dispatch with exactly one correct capability;
- OAuth-discovery path bypass.

It does **not** prove:

- a real Windows HMSBridge generation created an ephemeral token;
- a real pinned OpenAI tunnel child received the token;
- the child injected the header on a real forwarded MCP request;
- a real ChatGPT/OpenAI control-plane command traversed the tunnel;
- end-to-end MCP-to-Agent execution;
- pairing readiness or production readiness.

Those remain `STAGED_NOT_EXECUTED` until native Windows and live control-plane qualification.

## Next wiring tranche

The next atomic tranche should:

1. generate one token after HMSBridge runtime identity proof and before local MCP startup;
2. wrap the production MCP ASGI app with `McpTunnelIngressGate`;
3. pass the same token to the secure tunnel runtime without durable publication;
4. augment the already-scrubbed tunnel child environment using the `MCP_EXTRA_HEADERS` env indirection;
5. clear Python references on shutdown/failure as a best-effort measure (CPython strings are not zeroizable);
6. preserve current TLS -> MCP -> tunnel startup ordering and tunnel -> MCP -> TLS shutdown ordering;
7. add regression tests proving no token appears in argv/config/error surfaces and direct local `/mcp` calls cannot reach tools without the capability.
