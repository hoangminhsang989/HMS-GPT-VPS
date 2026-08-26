# R002F RFC 9701 signed introspection response verification

Status: `STAGED_NOT_EXECUTED`

This tranche adds a cryptographic verifier for one RFC 9701 signed token-introspection JWT. It remains deliberately isolated from the default HMSBridge production verifier until the configured authorization server is proven to advertise and return RFC 9701 responses.

## External contract

RFC 9701 requires a resource server to request:

`Accept: application/token-introspection+jwt`

and requires the authorization server response JWT to use:

`typ=token-introspection+jwt`

with top-level `iss`, `aud`, `iat`, and nested `token_introspection`.

The signed response is a stronger authenticity envelope than plain RFC 7662 JSON. It does not, by itself, prove how the OAuth client authenticated at the token endpoint. RFC 7662 service-specific members can be carried inside the nested `token_introspection` object, but any client-authentication attestation remains provider-specific unless standardized separately.

Reviewed references:
- https://www.rfc-editor.org/rfc/rfc9701.html
- https://www.rfc-editor.org/rfc/rfc7662.html
- https://developers.openai.com/plugins/build/auth
- https://pypi.org/project/cryptography/

## Dependency boundary

The verifier uses the maintained `cryptography` package for asymmetric signature verification.

`cryptography==50.0.0` is added only to:
- the `dev` extra; and
- the `bridge` extra.

It is not added to the base Agent dependency set.

## Verification boundary

`verify_rfc9701_signed_introspection_response()` requires an already-qualified `BridgeOAuthJwtIntrospectionCapabilityEvidence` and the exact authorization-server JWKS whose canonical SHA-256 matches that qualification.

The verifier rejects:
- non-canonical or malformed compact JWT encoding;
- duplicate JSON keys / unsupported JSON constants;
- JWT header schema drift;
- any `typ` other than exact `token-introspection+jwt`;
- algorithms or `kid` values outside the qualified authority;
- JWKS digest drift or private JWK material;
- JWK `alg` / `use` / `key_ops` mismatch;
- invalid RSA, RSA-PSS, ECDSA, Ed25519, or Ed448 signatures;
- issuer mismatch;
- resource-server audience mismatch;
- stale or future-dated `iat`;
- top-level claim schema drift;
- non-boolean nested `active`;
- inactive responses containing members other than exact `active=false`.

Supported signing families are restricted to the asymmetric algorithms already accepted by the RFC 9701 capability qualification:
- RS256 / RS384 / RS512
- PS256 / PS384 / PS512
- ES256 / ES384 / ES512
- EdDSA

The JWK used for the response must be a public signing key from the exact qualified JWKS.

## Deliberate proof boundary

Successful cryptographic verification may set only:

`signed_introspection_response_proven=true`

It deliberately keeps:

- `token_specific_client_auth_attestation_proven=false`
- `token_endpoint_private_key_jwt_exchange_proven=false`
- `chatgpt_app_oauth_client_proven=false`
- `chatgpt_ui_origin_proven=false`

Reason: a valid authorization-server signature authenticates the RFC 9701 response envelope and its nested introspection data. It still does not prove that the nested data contains a documented issuer-side statement that the exact token was minted after successful ChatGPT `private_key_jwt` authentication.

No project-level proof boolean is accepted from the signed payload itself.

## Production boundary

This tranche does not:
- send the live RFC 9701 introspection request;
- change the default production verifier;
- promote a generic RFC 7662 `client_id` into ChatGPT provenance;
- trust User-Agent, MCP `clientInfo`, `_meta`, forwarded headers, tunnel counters, redirect URIs, or public CIMD metadata as token-specific issuance proof.

The next bounded tranche is live-response retrieval authority: authenticated POST to the qualified introspection endpoint with exact `Accept: application/token-introspection+jwt`, bounded JWT response handling, and handoff to this verifier. That tranche must still remain blocked from `chatgpt_app_oauth_client_proven=true` unless the signed nested response contains a documented token-specific client-authentication statement.

Repository-wide pytest, GitHub CI, live authorization-server RFC 9701 exchange, live ChatGPT OAuth, Windows SCM, Hyper-V and full ChatGPT-to-Agent execution remain separate proof layers.
