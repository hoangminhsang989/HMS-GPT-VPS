# R002F — Production OAuth introspection authority

Status: `STAGED_NOT_EXECUTED`

This checkpoint replaces the intentionally unavailable HMSBridge OAuth verifier
with a standards-aligned Resource Server verifier based on RFC 8414 discovery
and RFC 7662 token introspection. It does not make HMSBridge an Authorization
Server and it does not introduce a development/static-token fallback.

## Resource Server model

`HMSBridge` remains an MCP OAuth Resource Server. The existing MCP server keeps
publishing protected-resource metadata through the MCP Python SDK using the
configured issuer, resource-server URL and the required `hms.vps.control`
scope.

The upstream bearer verifier is now an RFC 7662 introspection verifier. This
supports opaque access tokens as well as structured tokens because the
Authorization Server remains authoritative for active/revoked state.

## Authorization Server discovery

Startup derives the RFC 8414 metadata URL from the exact configured
`mcp_issuer_url`.

For an issuer with a path, the well-known segment is inserted between the host
and issuer path. Example:

`https://issuer.example/tenant`

becomes:

`https://issuer.example/.well-known/oauth-authorization-server/tenant`

The metadata response must:

- be obtained over HTTPS with normal platform certificate verification;
- return HTTP 200 and `application/json`;
- remain below the fixed response-size bound;
- contain no duplicate JSON keys or non-finite JSON constants;
- return `issuer` exactly equal to the configured issuer;
- provide an HTTPS `introspection_endpoint`;
- explicitly advertise `client_secret_basic` in
  `introspection_endpoint_auth_methods_supported`.

Redirects are not followed and environment HTTP proxies are not used by the
production request path.

## Introspection client credential

The Resource Server credential is stored at the fixed path:

`C:\ProgramData\HMS-GPT-VPS\Bridge\oauth-introspection-client.service-machine.dpapi`

The protected plaintext schema contains only:

- schema version;
- exact issuer URL;
- Resource Server introspection `client_id`;
- Resource Server introspection `client_secret`.

The issuer is part of the protected credential envelope and must exactly match
the runtime issuer before the credential can be published to the verifier.
This prevents credential reuse across Authorization Server issuers.

The credential is protected with LocalMachine DPAPI because privileged
provisioning and `NT SERVICE\HMSBridge` are different Windows identities. The
DPAPI scope is paired with an exact protected filesystem ACL:

- SYSTEM: FullControl;
- Builtin Administrators: FullControl;
- exact HMSBridge service SID: Read only on the credential file and
  ReadAndExecute on the fixed Bridge root.

The credential file is create-only. This checkpoint does not silently rotate
or replace an existing introspection credential.

Runtime loading proves the already protected Bridge runtime config, proves the
OAuth secret ACL/SHA, reads and decrypts the secret, re-proves the secret, then
re-proves the runtime config. A content/ACL race across that boundary fails
closed.

## Per-request bearer verification

Each bearer token is introspected whenever the MCP SDK asks the upstream token
verifier to authenticate it; active status is not cached by HMSBridge.

The verifier sends an RFC 7662 form POST containing only the bearer token and
`token_type_hint=access_token`. Resource Server authentication uses
`client_secret_basic`; the Resource Server secret is never placed in the POST
body, runtime JSON, SCM command line or exception text.

An introspection response is accepted only when all relevant authority facts
hold:

- `active` is exactly JSON boolean `true`;
- `iss` exactly equals the configured issuer;
- `client_id` is present and bounded;
- `sub` is present and bounded;
- `scope` is a valid unique OAuth scope list containing `hms.vps.control`;
- `aud` names the exact configured MCP resource URL;
- optional `token_type`, when present, is Bearer;
- optional `exp`, when present, is a future integer epoch;
- optional `nbf`, when present, is not in the future.

Only then is an MCP SDK `AccessToken` published. Network, TLS, discovery,
introspection, malformed-response, audience, issuer, subject, scope or expiry
failures return no authenticated token.

## Entrypoint ordering

The default HMSBridge runtime factory now follows:

`SCM token proof -> protected runtime config -> protected machine OAuth credential -> RFC 8414 discovery -> RFC 7662 verifier -> machine Agent/pairing secrets -> production assembly -> listener readiness`

No config path, client secret, access token or OAuth endpoint override is
accepted on the `hms-bridge service` command line.

## Validation boundary

Scratch/synthetic execution before publication:

- split OAuth credential/storage/HTTP/verifier suite: 11/11 PASS;
- service-entrypoint integration suite: 5/5 PASS;
- direct Python syntax compilation: PASS.

These results are not repository pytest, GitHub Actions, native Windows DPAPI,
real OAuth discovery/introspection, Windows SCM or Hyper-V qualification.

The following remain false:

- real OAuth Authorization Server credential provisioned;
- real RFC 8414 discovery proof;
- real RFC 7662 introspection proof;
- real `hms-bridge.exe` package/hash proof;
- real HMSBridge SCM/token proof;
- real LocalMachine-DPAPI cross-identity OAuth-secret proof;
- real Agent TLS/MCP listener proof;
- authenticated Agent transport proof;
- full Bridge command-flow proof;
- bootstrap retirement;
- pairing readiness.

PR #11 remains outside this checkpoint and must not be merged from it.
