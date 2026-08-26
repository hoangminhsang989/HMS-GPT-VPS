# R002F ChatGPT token-specific private_key_jwt attestation capability

Status: `STAGED_NOT_EXECUTED`

This tranche stages a fail-closed verifier capability for a stronger OAuth proof boundary than generic RFC 7662 `client_id`.

## Why this exists

RFC 7662 binds an introspection response to the exact token presented to the authorization server and allows service-specific extension members, but it does not standardize a response member proving which client-authentication method was used at the token endpoint.

MCP Client ID Metadata Documents may advertise `private_key_jwt`, and the qualified ChatGPT CIMD/JWKS authority describes the public signing keys, but neither fact proves that the exact bearer token currently accepted by HMS was minted after a successful ChatGPT `private_key_jwt` assertion.

Therefore `client_id` alone remains insufficient for this proof layer.

## Staged contract

`BridgeOAuthChatGptPrivateKeyJwtVerifier` composes the existing authenticated RFC 7662 verifier with a mandatory issuer-side extension on the same token-specific introspection response:

`client_auth_attestation`

The nested object has an exact schema:

- `verified` must be exact boolean `true`;
- `method` must be exact `private_key_jwt`;
- `client_id` must equal the exact case-sensitive ChatGPT CIMD client ID;
- `jwks_uri` must equal `https://chatgpt.com/oauth/jwks.json`;
- `kid` must be one of the signing-key identifiers observed during a fresh ChatGPT CIMD/JWKS qualification.

Unknown/missing fields, method drift, client drift, JWKS drift, unknown signing key, inactive token, wrong audience/resource, missing scope, expiry/nbf failure or malformed RFC 7662 evidence all fail closed.

The sync builder performs fresh ChatGPT CIMD/JWKS qualification itself before constructing the verifier; it does not accept a caller-provided evidence object as production authority.

## Proof boundary

This is a capability, not a live provider claim.

The extension name/schema is service-specific and MUST NOT be enabled in production unless the configured authorization server explicitly documents and actually returns equivalent authenticated token-specific evidence. If the issuer does not provide such evidence, HMS must reject promotion rather than infer it from `client_id`, User-Agent, MCP `clientInfo`, `_meta`, forwarded headers, tunnel metrics, redirect URIs or public CIMD/JWKS metadata.

A successful verifier result carries only the validated client-auth facts (`client_auth_method`, `client_auth_jwks_uri`, `client_auth_kid`, and an internal attestation schema version). It deliberately does **not** place project-level proof booleans in `AccessToken.claims`, because a dependency-injected verifier must not be able to promote project authority by synthesizing claims.

Until a real issuer response is executed and the production principal boundary independently requires this exact verifier path:

- `token_endpoint_private_key_jwt_exchange_proven=false`;
- `chatgpt_app_oauth_client_proven=false`;
- `chatgpt_ui_origin_proven=false`.

No ChatGPT private key, client secret, bearer token, authorization code, refresh token or callback secret is persisted by this tranche.

## Deliberately not wired into default production

The current HMSBridge default verifier remains the exact-client RFC 7662 verifier until a real issuer-side extension or equivalent provider attestation is qualified. This prevents a fabricated project-local convention from becoming a false production proof.

Repository pytest, GitHub CI, live issuer introspection, live ChatGPT OAuth, Windows SCM, Hyper-V and full ChatGPT-to-Agent execution remain separate proof layers.
