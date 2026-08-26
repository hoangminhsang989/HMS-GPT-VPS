# R002F ChatGPT CIMD metadata authority

Status: `STAGED_NOT_EXECUTED`

This tranche adds a read-only, fail-closed qualification boundary for the OAuth client metadata that OpenAI currently documents for ChatGPT connectors.

## Reviewed external contract

OpenAI's current authentication documentation says that ChatGPT can identify as the OAuth client by using a Client ID Metadata Document (CIMD) URL such as `https://chatgpt.com/oauth/.../client.json`. It also says ChatGPT's production CIMD advertises `none` and `private_key_jwt`; when the authorization server supports `private_key_jwt`, ChatGPT prefers it, publishes a public JWKS at `/oauth/jwks.json` on the metadata origin, and signs token requests server-side with an OpenAI-managed private key.

The current MCP authorization specification requires a CIMD document to self-bind its `client_id` to the document URL and include `client_name` and `redirect_uris`. The CIMD draft describes `private_key_jwt` with a public `jwks_uri`.

Reviewed references:
- https://developers.openai.com/plugins/build/auth
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-00.html

## Qualification

`qualify_chatgpt_cimd_authority_sync()` performs no mutation and accepts no OAuth secret.

It requires:
- an exact configured HTTPS issuer;
- an exact canonical `chatgpt.com` CIMD `client_id` under the reviewed `/oauth/.../client.json` path family;
- authorization-server metadata that explicitly supports CIMD, `private_key_jwt`, and S256 PKCE;
- CIMD self-binding of `client_id`;
- at least one current `https://chatgpt.com/connector/oauth/{callback_id}` redirect URI;
- exactly the reviewed ChatGPT client-auth capability set `none` + `private_key_jwt`;
- exact JWKS authority `https://chatgpt.com/oauth/jwks.json`;
- bounded public signing JWKS with no private JWK members;
- stable authorization-server authority, CIMD authority, and JWKS across a before/after read.

The existing hardened OAuth HTTPS helper is reused: default system TLS validation, no redirects, no proxy inheritance, bounded JSON, duplicate-key rejection, and no secret request body.

## Deliberate proof boundary

A successful metadata qualification may set only:

`chatgpt_cimd_metadata_authority_proven=true`

It deliberately keeps:

- `token_endpoint_private_key_jwt_exchange_proven=false`
- `chatgpt_app_oauth_client_proven=false`
- `chatgpt_ui_origin_proven=false`

Reason: a public metadata document and JWKS prove what ChatGPT declares and which public keys are authoritative. They do not prove that the access token currently presented to HMS was minted after an authorization server successfully verified a ChatGPT `private_key_jwt` client assertion.

The next proof layer therefore needs issuer-side evidence tied to the exact token issuance/exchange. Generic RFC 7662 `client_id` alone is insufficient unless the trusted issuer also provides an authenticated, token-specific statement that the client authentication method was `private_key_jwt` (or an equivalent provider-side audit/attestation).

Secure MCP Tunnel transport provenance remains a separate trust boundary. A local HMS MCP server behind `tunnel-client` must not claim direct visibility of the OpenAI-managed mTLS certificate used at an external ChatGPT-to-MCP TLS edge.

Repository pytest, GitHub CI, live ChatGPT CIMD retrieval through the product flow, live authorization-server token exchange, Windows SCM, Hyper-V, and full ChatGPT-to-Agent execution remain separate proof layers.
