# R002F MCP Bridge Adapter Authority

Status: **STAGED_NOT_EXECUTED**

Branch authority before this tranche: `fcf84fc0e2e22c90c63e9997895a0f19716de513`.

## Purpose

Expose the already principal-bound HMS Bridge control facade through the current
MCP Python SDK without turning the Windows host or managed guest into a public
HTTP command server.

The intended topology is:

`ChatGPT / supported MCP client -> authenticated MCP transport -> HMS local MCP adapter -> principal-bound Bridge control facade -> signed durable Agent command queue -> outbound managed guest Agent -> guest policy/action runtime`

The MCP adapter is not an executor. It never runs workspace/process operations on
the physical Bridge host.

## Current SDK contract

This tranche targets MCP Python SDK v2, the current stable line, and uses:

- `from mcp.server import MCPServer`;
- `TokenVerifier` + `AccessToken`;
- `AuthSettings`;
- `get_access_token()` for per-request HTTP identity;
- `ToolAnnotations` with v2 snake_case Python fields;
- Streamable HTTP rather than SSE;
- stateless JSON responses.

The SDK authentication boundary applies to HTTP transports. This tranche does
not expose or support stdio because stdio has no HTTP bearer-auth middleware.

## Deployment boundary

`run_loopback_mcp_server()` hard-codes `127.0.0.1`. There is no configuration
field that may change the listener to `0.0.0.0` or another public interface.

The expected remote deployment is a private/account-or-workspace-scoped tunnel or
other independently reviewed private connector that reaches the loopback MCP
server. This tranche does not create, configure or prove a Secure MCP Tunnel.

`resource_server_url` is the externally authoritative HTTPS MCP resource expected
in bearer tokens. It is deliberately separate from the local loopback listen
address.

## OAuth principal authority

The deployment supplies a real OAuth `TokenVerifier`. HMS wraps it with
`ResourceBoundTokenVerifier` and accepts the resulting `AccessToken` only when:

- `client_id` is an actual non-empty string;
- `subject` is an actual non-empty string;
- `claims["iss"]` exactly equals configured `issuer_url`;
- `resource` exactly equals configured `resource_server_url`;
- scopes are a unique list of strings containing `hms.vps.control`;
- optional `expires_at` is an exact positive integer and is not expired.

A missing subject fails closed. HMS does not degrade a user-specific write/control
session to client-only identity.

The internal `TrustedIntegrationPrincipal` is derived from a domain-separated
SHA-256 over the trusted `(issuer, client_id, subject)` tuple. Raw OAuth bearer
tokens and raw user subjects are not placed into tool output or persisted by this
adapter.

No tool schema contains `principal`, `principal_id`, `subject`, `issuer`,
`client_id`, `is_trusted` or an equivalent caller-controlled identity selector.

## Tool contract

### `pair_vps(pairing_link)`

Consumes/binds the local one-time pairing link through `PrincipalPairingService`.
The result contains only instance/session metadata, scopes and expiry. It never
returns the pairing token, raw session bearer token or OAuth access token.

Annotation intent:

- read-only: false;
- destructive: false;
- idempotent: true for the exact authenticated principal/link authority;
- open-world: false.

### `read_file(instance_id, request_id, path)`

Routes `workspace.read` through the principal-bound Bridge facade and outbound
managed Agent. It may return `pending` until the Agent result is durable; retrying
with the same `request_id` converges on the same command/result authority.

Annotation intent: read-only, non-destructive, idempotent, closed-world.

### `write_file(instance_id, request_id, path, content)`

Routes only create-mode `workspace.write`. It cannot overwrite an existing file.
`workspace.write mode=replace` remains unavailable until a separate explicit
approval UX and approval-proof binding are designed and qualified.

Annotation intent: mutating but non-destructive, idempotent for the same
`request_id`, closed-world.

## Error disclosure

Adapter-facing security failures are translated to fixed error codes such as:

- `pairing_rejected`;
- `pairing_unavailable`;
- `agent_unavailable`;
- `command_ambiguous`;
- `control_conflict`;
- `approval_required`.

The adapter does not reflect pairing links, bearer tokens, file paths from
internal exceptions, DPAPI paths, SQLite paths or verifier exception text.

## Dependency isolation

MCP is a Bridge-side optional dependency, not a core guest Agent dependency.

`pyproject.toml` stages:

- `bridge = ["mcp>=2,<3"]`;
- the same MCP dependency in `dev` so CI can execute adapter regressions.

The base install and packaged guest Agent remain free of the MCP SDK unless the
Bridge extra is explicitly installed.

## Staged regression authority

`tests/test_r002f_mcp_bridge_server.py` covers:

- exact accepted OAuth resource/issuer/subject/scope/expiry;
- rejection of wrong resource, wrong issuer, missing subject, missing scope and
  expired bearer authority;
- stable principal derivation from authenticated token identity;
- model-facing adapter methods deriving principal only from auth context;
- missing auth context rejection;
- pairing error sanitization without secret echo;
- MCPServer v2 construction with HTTP auth configuration;
- loopback-only Streamable HTTP runner arguments;
- rejection of non-HTTPS authority URLs and bool-as-int port values.

These remain staged source/regression claims until a real test runner installs the
Bridge/dev extra and executes the suite.

## Explicit non-claims

This tranche does not prove:

- a real OpenAI/ChatGPT OAuth verifier;
- a real Secure MCP Tunnel;
- a ChatGPT workspace/account connection;
- a real MCP HTTP request carrying an authenticated principal;
- a real Bridge -> Hyper-V guest command;
- real file creation/readback inside the guest;
- production pairing readiness.

Project proof boundaries remain false until independently qualified:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`
