# R002F — MCP ingress generation foundation

Status: `STAGED_NOT_EXECUTED`

This tranche stages a non-secret per-HMSBridge-start ingress generation that can later bind one protected `/mcp` request to the same live Secure MCP Tunnel generation without persisting the tunnel ingress capability secret.

## Authority

HMSBridge already creates one fresh 64-lowercase-hex `mcp_ingress_token` for each production-service start and passes that exact secret to both the MCP ingress gate and the Secure MCP Tunnel runtime.

This tranche derives a non-secret 32-lowercase-hex generation from that already-shared token using domain-separated SHA-256:

`SHA256("hms-gpt-vps/mcp-tunnel-ingress-generation/v1\\0" || ingress-token-ascii)[0:32]`

The raw token remains the only ingress capability. The generation cannot authorize `/mcp` and is safe to publish as evidence.

## Protected request context

`McpTunnelIngressGate` computes the generation once from its validated token. It sets that generation into a `ContextVar` only after all of these gates pass:

1. exact HTTP `/mcp` path;
2. exact single ingress header;
3. canonical 64-lowercase-hex header value; and
4. constant-time equality with the per-start secret capability.

The context is reset in `finally`, including when downstream MCP handling raises. OAuth discovery and every non-`/mcp` route bypass the gate without receiving an ingress generation context.

`current_mcp_tunnel_ingress_generation()` therefore exposes only a non-secret marker to code already executing inside one capability-authenticated MCP request. It never exposes the capability token.

## Tunnel health generation

`SecureMcpTunnelRuntime` derives the exact same generation from its existing `mcp_ingress_token` and uses it as the health attempt identity:

`<runtime-root>/tunnel-health/attempt-<generation>/health-url.txt`

No runtime/factory signature changes are required. The runtime still requires the attempt path to be new and non-redirected. Existing fail-closed startup, readiness, package, child-process, secret, and shutdown behavior is unchanged. Runtime evidence now includes the non-secret generation.

## Deliberate proof boundary

This tranche does **not** yet change the native tunnel qualifier or durable principal-dispatch authority. It therefore cannot by itself prove that one durable MCP request traversed one exact native tunnel generation.

The next tranche must independently extract the generation from the active native `attempt-<32hex>` path and then atomically bind the request-context generation to durable dispatch authority.

These remain false until that later proof exists:

- `mcp_adapter_invocation_proven`
- `openai_control_plane_origin_proven`
- `full_bridge_command_flow_proven`

## Validation performed while staging

Focused dependency-isolated regression: **33/33 PASS** across the existing ingress/tunnel/service suites plus generation-specific tests.

Covered generation-specific properties:

- deterministic canonical generation derivation;
- malformed token rejection;
- generation context only after exact capability acceptance;
- context reset after success and exception;
- no context on OAuth discovery/non-`/mcp` routes; and
- exact tunnel health attempt directory derived from the same token.

Candidate source/tests compile successfully.

Repository pytest: NOT RUN in this environment.
Real Windows / Hyper-V / SCM / LocalMachine-DPAPI / OpenAI tunnel / ChatGPT connector execution: NOT RUN.
