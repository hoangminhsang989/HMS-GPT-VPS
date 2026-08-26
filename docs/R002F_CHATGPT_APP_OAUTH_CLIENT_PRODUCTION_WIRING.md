# R002F ChatGPT App OAuth Client Production Wiring

Status: `STAGED_NOT_EXECUTED`

This tranche makes one exact OAuth token `client_id` mandatory in the protected HMSBridge production runtime configuration and enforces it twice before MCP principal authority can be used.

## Runtime authority

`BridgeServiceRuntimeConfig` is schema version 3 and requires the non-secret field:

`mcp_expected_client_id`

Version 2 and configurations missing the field fail closed. There is no implicit migration and no production default.

The field is canonical text, at most 512 characters, with no edge whitespace or ASCII control characters. It is published inside the existing create-only, ACL-pinned protected runtime configuration. It is not a client secret.

## Two independent enforcement layers

1. The default RFC 7662 verifier receives the configured expected client ID and refuses to publish an `AccessToken` when trusted introspection returns another client.
2. `HmsMcpBridgeConfig` carries the same authority and `_validate_access_token()` checks exact case-sensitive equality again. This protects the principal boundary if a different or dependency-injected upstream verifier is supplied.

Production conversion from `BridgeServiceRuntimeConfig` always passes the same `mcp_expected_client_id` to the MCP configuration.

## What this can prove

After real qualification against the intended OAuth issuer and the provider-side ChatGPT app registration, this boundary may support:

`chatgpt_app_oauth_client_proven=true`

with the narrow meaning that the authenticated bearer token was issued/introspected for the exact configured OAuth client identity.

It does not prove:

- a specific ChatGPT UI click, message, user gesture, browser instance or conversation;
- that ordinary MCP `clientInfo`, User-Agent, `_meta`, tunnel metrics or forwarded request headers are trustworthy provenance;
- full ChatGPT-to-Agent command flow by itself.

Therefore `chatgpt_ui_origin_proven=false` and `full_bridge_command_flow_proven=false` remain required until separately proven.

## Secret separation

The existing HMSBridge introspection client credential remains a separate LocalMachine-DPAPI secret used by HMSBridge to authenticate to the issuer's introspection endpoint. This tranche does not store a ChatGPT OAuth client secret, callback URI, bearer token, pairing token or tunnel API key in the runtime config.

## Validation boundary

Candidate checks for this tranche are focused/static/synthetic only unless explicitly reported otherwise. Repository pytest, GitHub CI, Windows SCM execution, live RFC 7662 introspection, live ChatGPT OAuth and Hyper-V execution remain separate proof layers.
