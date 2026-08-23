# R002C Pairing and Control Authority

Status: `FOUNDATION_IN_PROGRESS`

This document defines the current R002C Tranche 5 pairing/control contract. It is code-level authority only. It does **not** declare the real Windows Agent transport, ChatGPT connector/MCP surface, or Hyper-V end-to-end path runtime PASS.

## 1. Boundary

The permanent control path remains:

`supported ChatGPT/HMS integration -> Bridge auth/control core -> authenticated outbound HMS Agent session -> policy-gated Agent action -> C:\HMS-Workspace`

The physical Hyper-V host Administrator surface is not exposed to ChatGPT. PowerShell Direct remains bootstrap/finalization transport only and is not the permanent control channel.

## 2. Pairing grant

A pairing grant is temporary bootstrap authorization for a compatible HMS integration.

Locked properties:

- 256-bit random pair token;
- default TTL 10 minutes, maximum 30 minutes;
- HTTPS Bridge URL required;
- raw token is placed in URL fragment `#token=...`, not query parameters;
- persistent pairing record stores token SHA-256 only;
- scopes are restricted to the canonical minimum set:
  - `workspace.read`
  - `workspace.write`
  - `process.test`
  - `git.status`
  - `audit.read`
- missing timestamps, invalid temporal order, unsupported scopes, wrong instance, expired, revoked or invalid records fail closed.

A pasted URL alone does not give an ordinary ChatGPT conversation shell access. A compatible connector/MCP/action integration must explicitly implement this protocol.

## 3. Atomic pairing -> initial session exchange

`PairingSessionExchange` requires `PairingStore` and `ControlSessionStore` to share one SQLite database.

The first successful exchange commits all of the following in one `BEGIN IMMEDIATE` transaction:

1. consume the pairing record;
2. persist the client nonce SHA-256 binding;
3. insert exactly one initial control-session record.

The raw pair token, raw client nonce, raw session token and Bridge exchange root key are never persisted in SQLite.

### Crash recovery

The client generates a fresh random exchange nonce and sends it with the original pair token.

The initial session credential is deterministically derived from:

- Bridge exchange root key;
- pair token;
- pair ID;
- managed instance ID;
- original client nonce;
- domain-separated HMAC labels.

This deterministic derivation exists only to recover from the post-commit/pre-response crash window without storing the raw session token.

A recovery retry is accepted only when all are true:

- pairing was already consumed;
- pair token still matches the original digest;
- exact original client nonce matches the stored nonce SHA-256;
- request is within the 60-second recovery window;
- derived initial session identity matches the committed exchange binding;
- committed session record has not been rotated, revoked or otherwise changed.

A different nonce, different Bridge key, expired recovery window or changed initial session fails closed. Recovery returns the same initial session and never creates a second session.

## 4. Bridge exchange root key

`PairingExchangeKeyStore` is the create-once persistent root-key store.

Production default:

- 32-byte random key;
- current-user Windows DPAPI `CryptProtectData` / `CryptUnprotectData`;
- no DPAPI UI;
- key excluded from `repr`;
- on-disk file contains only a non-secret format marker and DPAPI ciphertext;
- fsynced same-directory temporary file;
- create-only hard-link publication, never `replace()`;
- existing invalid/corrupt/unprotectable file fails closed and is never silently replaced;
- protected payload has a bounded maximum size;
- no API in this tranche silently clears or rotates the root key.

The concrete product-managed secret path remains an assembly/runtime concern and must be outside Git, source workspaces and normal audit output.

## 5. Control sessions

A control session is separate from the pairing token.

Locked properties:

- independent high-entropy session token;
- token SHA-256 only at rest;
- exact `instance_id` binding;
- exact granted scope set;
- timezone-aware issue/expiry timestamps;
- epoch-based rotation;
- rotation cannot expand scopes;
- old token becomes invalid immediately after successful rotation;
- explicit revocation supported;
- concurrent rotation is serialized in SQLite so only one next epoch wins.

## 6. Control request surface

The network request schema contains:

- schema version;
- request ID;
- instance ID;
- session ID;
- action;
- action parameters.

The raw session token is supplied separately and is excluded from request hashing, request objects, persisted idempotency records and normal audit detail.

Only these five actions are accepted in the current minimum surface:

- `workspace.read`
- `workspace.write`
- `process.test`
- `git.status`
- `audit.read`

## 7. Authentication, authorization and idempotency

`ControlGateway` order is locked:

1. authenticate session token;
2. verify exact instance/session identity;
3. verify required scope;
4. apply idempotency claim/replay semantics;
5. permit action execution only for a fresh claim.

Unauthorized callers cannot use a known request ID to retrieve a cached response.

`IdempotencyStore` persists `CLAIMED` before side effects and `COMPLETED` only after a response is committed. A crash in the ambiguous window leaves the request unresolved and automatic replay is blocked instead of repeating a possibly completed side effect.

## 8. Trusted local approval

Remote control requests cannot self-approve destructive work.

`TrustedLocalApproval` is intentionally absent from the network request schema. It is minted only by a trusted local operator/UI boundary and is bound to:

- exact request ID;
- exact instance ID;
- exact action;
- exact request SHA-256;
- short approval lifetime.

For the current action set, replacing an existing workspace file is destructive and requires trusted local approval plus an `expected_sha256` precondition. Creating a new file does not imply permission to overwrite an existing file.

## 9. Minimum action runtime

`ControlActionRuntime` reuses the existing R001 `Workspace`, fail-closed policy, policy-gated executor and append-only audit primitives.

### `workspace.read`

- workspace-bound path resolution;
- file only;
- maximum 1 MiB;
- UTF-8 or base64 response;
- SHA-256, size and UTC modified time returned;
- content itself is not written to normal audit metadata.

### `workspace.write`

- workspace-bound path resolution;
- UTF-8 text only;
- maximum 1 MiB;
- `create` uses create-exclusive semantics;
- `replace` requires trusted local approval and exact existing SHA-256;
- atomic temporary-file replacement for approved replace;
- all `.git` metadata paths are denied, including case variants, Windows separator variants, trailing dot/space normalization and `.git:` ADS forms;
- no delete action exists in the current remote surface.

### `process.test`

- fixed `python -m pytest <workspace-target> -q` shape;
- only bounded `fail_fast`, `maxfail` and timeout controls;
- no arbitrary shell string or arbitrary pytest argument injection;
- normal R001 policy gate still applies.

### `git.status`

Fixed read-only command:

`git status --short --branch --untracked-files=all`

### `audit.read`

- bounded tail read;
- current maximum 100 events.

Command stdout/stderr returned by `process.test` and `git.status` are capped at 256 KiB each with truncation metadata.

## 10. Verification currently present

Code-level regression coverage includes:

- one-time/expired/revoked pairing behavior;
- concurrent pairing consumption;
- atomic pairing/session exchange;
- nonce-bound bounded crash recovery;
- wrong nonce / wrong Bridge key / rotated-session recovery rejection;
- no raw pair token, session token, client nonce or Bridge key in SQLite;
- DPAPI key-store native Windows round trip plus injected cross-platform tests;
- concurrent create-once root-key publication;
- session scope/expiry/rotation/revocation/concurrent rotation;
- request hashing and secret exclusion;
- gateway auth-before-idempotency;
- ambiguous crash replay blocking;
- workspace create/read/replace/path-escape/.git denial;
- fixed pytest and Git-status command shapes;
- bounded command output;
- trusted local approval binding;
- in-process authenticated create -> replay -> read SHA-256 proof.

## 11. Explicitly not yet proven

The following remain required before Tranche 5 can be called runtime PASS:

- real HMS Agent executable implementing these capabilities as a non-admin Windows service;
- outbound Agent -> Bridge authenticated transport and reconnect semantics;
- device identity/key lifecycle for Agent transport;
- real Bridge network endpoints for pair/session/control exchange;
- compatible ChatGPT MCP/connector/action integration;
- TLS deployment and network-level replay/logging tests;
- real Hyper-V guest end-to-end file create/read proof through the Agent transport;
- visible CI result for the current direct-push HEAD;
- target-Windows Hyper-V integration evidence.

## 12. Canonical end-to-end acceptance target

Through the supported authenticated HMS integration, ChatGPT creates:

`C:\HMS-Workspace\chatgpt-control-test.txt`

inside the managed Windows VM, then reads it back through the same Agent control path and receives matching SHA-256, byte size, timestamp and audit event ID, without host filesystem sharing and without physical-host Administrator control.
