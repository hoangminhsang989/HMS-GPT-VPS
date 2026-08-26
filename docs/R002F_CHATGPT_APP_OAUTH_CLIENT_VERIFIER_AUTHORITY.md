# R002F ChatGPT App OAuth Client Verifier Authority

Status: `STAGED_NOT_EXECUTED`

This tranche adds a narrow RFC 7662 verifier capability for an exact expected OAuth token `client_id`.
It does not claim ChatGPT UI/user-gesture origin and it does not yet make the expected client ID mandatory in the production HMSBridge runtime config.

## Authority boundary

`BridgeOAuthIntrospectionTokenVerifier` may be constructed with `expected_client_id`.
When present, an otherwise active token is rejected unless the trusted introspection response contains the exact same case-sensitive `client_id`.
The value is non-secret; it is not the HMSBridge introspection credential client ID and it is not a client secret.

The HMSBridge introspection credential remains a separate LocalMachine-DPAPI secret used only to authenticate HMSBridge to the issuer's introspection endpoint.
No ChatGPT OAuth client secret, callback URI, bearer token, or MCP metadata is stored by this tranche.

## Proof semantics

A future production configuration that pins the OAuth client ID may support a narrow statement such as `chatgpt_app_oauth_client_proven=true` when combined with trusted issuer/introspection evidence and the provider-side confidential-client registration authority.
It must not imply `chatgpt_ui_origin_proven=true`: bearer-token possession and OAuth client identity do not prove a specific ChatGPT UI click, message, or user gesture.

## Fail-closed constraints

- exact case-sensitive client-ID equality;
- invalid/empty/control-character/oversized expected IDs are rejected;
- mismatch returns no `AccessToken`;
- issuer, audience, scope, time and bearer grammar checks remain unchanged;
- no User-Agent, MCP `clientInfo`, `_meta`, tunnel metrics, or forwarded command header is treated as ChatGPT provenance.

## Validation boundary

Candidate validation for this tranche is focused/static only. Repository pytest, Windows service execution, real issuer introspection, real ChatGPT OAuth, and real Hyper-V execution remain unproven until separately executed.
