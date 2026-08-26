# R002F RFC 9701 signed introspection capability authority

Status: `STAGED_NOT_EXECUTED`

This tranche adds a read-only, fail-closed qualification boundary for authorization servers that can return signed JWT token-introspection responses under RFC 9701.

## External authority audit

Current OpenAI authentication documentation says ChatGPT uses `private_key_jwt` when both the ChatGPT CIMD and the configured authorization server support it. ChatGPT signs the token request with an OpenAI-managed key and the authorization server verifies that assertion against the public ChatGPT JWKS.

That proves the verification duty exists at the token endpoint. It does not define a standardized claim that a downstream MCP resource server can later read to prove which client-authentication method was used for one already-issued access token.

RFC 7662 allows service-specific introspection response members, but does not standardize token-endpoint client-authentication evidence.

RFC 9701 provides a stronger response envelope: a signed token-introspection JWT with issuer, audience, issued-at time, and a nested `token_introspection` object. It also registers authorization-server metadata fields describing supported introspection response signing algorithms.

Reviewed authority:
- https://developers.openai.com/plugins/build/auth
- https://www.rfc-editor.org/rfc/rfc7662.html
- https://www.rfc-editor.org/rfc/rfc9701.html

## Capability qualification

`qualify_rfc9701_signed_introspection_capability_sync()` performs no mutation and accepts no bearer token or OAuth secret.

It requires stable before/after authorization-server metadata with:
- exact configured HTTPS issuer;
- HTTPS introspection endpoint;
- the existing HMS `client_secret_basic` introspection authentication method;
- non-empty `introspection_signing_alg_values_supported`;
- only approved asymmetric signing algorithms;
- HTTPS `jwks_uri`.

It then reads the authorization-server JWKS twice and requires:
- bounded non-empty public signing keys;
- no private JWK members;
- unique `kid` values;
- at least one key whose type/algorithm matches an advertised introspection signing algorithm;
- byte-equivalent canonical metadata/JWKS authority across the before/after reads.

## Deliberate proof boundary

A successful qualification may set only:

`rfc9701_signed_introspection_capability_proven=true`

It deliberately keeps:

- `signed_introspection_response_proven=false`
- `token_specific_client_auth_attestation_proven=false`
- `token_endpoint_private_key_jwt_exchange_proven=false`
- `chatgpt_app_oauth_client_proven=false`
- `chatgpt_ui_origin_proven=false`

Reason: advertising signed introspection support and publishing stable signing keys do not prove that HMS received and cryptographically verified a signed introspection response for the exact bearer token, and do not prove that the nested introspection data contains provider-authenticated evidence that the token endpoint used ChatGPT `private_key_jwt`.

## Production boundary

This module is deliberately not wired into the default HMSBridge production verifier.

The next tranche may implement RFC 9701 response retrieval and signature verification only if the configured authorization server actually advertises the capability. Even after signature verification, project authority must remain blocked unless the signed nested token-introspection data contains an issuer-defined, documented token-specific statement equivalent to successful `private_key_jwt` client authentication.

No User-Agent, MCP `clientInfo`, `_meta`, forwarded header, tunnel metric, public CIMD metadata, or generic RFC 7662 `client_id` may substitute for that evidence.

Repository-wide pytest, GitHub CI, live issuer signed introspection, live ChatGPT OAuth, Windows SCM, Hyper-V and full ChatGPT-to-Agent execution remain separate proof layers.
