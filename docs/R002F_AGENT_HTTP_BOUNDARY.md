# R002F Agent HTTP Boundary Authority

Status: `STAGED_NOT_EXECUTED`

This tranche exposes the existing authenticated `AgentBridgeService` through a strict HTTP request/response boundary without opening a socket or creating a second transport protocol.

## Exact wire compatibility

The boundary matches the existing outbound `AgentHttpsClient` contract:

- method: `POST` only;
- paths: `/agent/v1/hello`, `/agent/v1/heartbeat`, `/agent/v1/poll`, `/agent/v1/result` only;
- request media type: `application/json` with optional canonical `charset=utf-8`;
- exact `Content-Length` required;
- `Transfer-Encoding` rejected;
- body bound: `MAX_AGENT_BODY_BYTES` (2 MiB);
- response: HTTP 200 + `application/json` for successful authenticated service calls;
- `Cache-Control: no-store` on every response.

## Header authority

`AgentBridgeHttpRequest.headers` preserves raw header occurrences as a tuple of `(name, value)` pairs. This is deliberate: a listener must not collapse native HTTP headers into a dictionary before this boundary, because doing so could hide duplicate authentication headers.

The boundary rejects duplicate names case-insensitively before HMAC verification. Only the nine signed HMS authentication headers are forwarded into `AgentSignedRequest`:

- `X-HMS-Agent-Schema`
- `X-HMS-Device-Id`
- `X-HMS-Instance-Id`
- `X-HMS-Boot-Id`
- `X-HMS-Connection-Epoch`
- `X-HMS-Timestamp`
- `X-HMS-Nonce`
- `X-HMS-Content-SHA256`
- `Authorization`

Ambient metadata such as cookies, forwarding headers, proxy headers, User-Agent and Accept are not HMAC authority.

## Failure surface

Network-facing failures are fixed, secret-free JSON classes:

- 400 `invalid_http_request`
- 400 `invalid_agent_request`
- 401 `authentication_failed`
- 409 `agent_state_conflict`
- 413 `request_too_large`
- 503 `bridge_unavailable`

Resolver, SQLite, HMAC and request-body exception detail is never serialized onto the response body.

## Production composition

`BridgeProductionAssembly` now constructs `agent_http = AgentBridgeHttpBoundary(agent_bridge)`, proving that the Agent-facing HTTP boundary and the MCP/principal-control façade share the same exact `AgentBridgeService`, presence registry and durable command store.

The assembly still does **not** open an Agent listener. A later deployment tranche must provide TLS/socket ownership and must preserve raw HTTP header occurrences when creating `AgentBridgeHttpRequest`.

## Regression staged

`tests/test_r002f_agent_bridge_http_boundary.py` stages:

- valid signed `hello` crossing the HTTP boundary and updating presence;
- wrong HMAC → secret-free 401 and no presence mutation;
- duplicate case-insensitive Authorization header → 400 before mutation;
- `Transfer-Encoding` and mismatched `Content-Length` → 400 before mutation;
- request body over 2 MiB → 413 before header/service processing;
- authenticated `poll` returns the exact signed pending Bridge command;
- successful responses remain compatible with the existing Agent HTTPS client (`200`, `application/json`, exact response length).

`tests/test_r002f_bridge_production_assembly.py` additionally asserts `assembly.agent_http.service is assembly.agent_bridge`.

## Explicit non-claims

This tranche does not prove:

- an actual TLS listener;
- certificate provisioning or rotation;
- firewall/NAT/relay deployment;
- a real outbound Agent HTTPS exchange;
- pytest/GitHub Actions execution;
- full Bridge command completion;
- a live Secure MCP Tunnel or ChatGPT session.

Project proof flags remain false until the corresponding execution gates pass.
