# Security Baseline — HMS-GPT-VPS

## Default posture

HMS-GPT-VPS is fail-closed. Missing, malformed, expired, ambiguous, or unauthorized requests are denied.

## Privilege model

- Run the agent under a dedicated unprivileged operating-system account.
- Do not grant unrestricted passwordless sudo.
- Add privileged operations only through narrowly scoped allow rules.
- Secrets must come from protected runtime configuration or a secret store, never committed plaintext.

## Filesystem policy

- Only configured project roots are accessible.
- Resolve paths canonically before authorization.
- Reject traversal outside an authorized root.
- Symlink and mount-boundary behavior must be tested before production enablement.

## Destructive operations

Operations that delete, irreversibly overwrite, discard history/data, or have materially equivalent effects require explicit approval. Examples include file/directory deletion, destructive Git resets/cleans, database drops, storage pruning, and destructive deployment actions.

## Command execution

- Commands are evaluated against capability and project scope.
- Timeouts and output limits are mandatory.
- Environment variables are filtered.
- Shell invocation should be avoided where a direct executable call is sufficient.
- Every execution receives an audit identifier.

## Network exposure

- No anonymous remote execution endpoint.
- Bind locally by default during development.
- Production remote access must use strong authentication and encryption.
- Replay protection and session expiration are required before Internet exposure.

## Audit

Record at minimum: timestamp, request/audit ID, actor/session identity, project scope, requested capability, decision, command/action summary, exit result, and approval reference for privileged/destructive actions.

## Production gate

Internet-facing deployment is prohibited until authentication, authorization, replay protection, audit logging, project isolation, and destructive-action tests pass.
