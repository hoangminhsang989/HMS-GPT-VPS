# R002F — HMSBridge OAuth introspection credential provisioning ingress

Status: `STAGED_NOT_EXECUTED`

This tranche adds the privileged ingress used to place the OAuth RFC 7662
introspection client credential into the existing LocalMachine-DPAPI
HMSBridge secret authority.

## Security boundary

`hms-bridge provision-oauth-introspection-credential` accepts no credential,
secret, runtime-config path, or storage-path arguments.

The required input is one bounded UTF-8 JSON object on stdin with exactly:

- `issuer_url`
- `client_id`
- `client_secret`

The command proves an effective elevated Administrator process token and an
SCM service named `HMSBridge` configured as `NT SERVICE\HMSBridge`, `Manual`,
and `Stopped` **before stdin is read**. It repeats that proof immediately
before create-only publication and again after publication. The service SID
must remain stable across the operation.

The secret is stored only through the existing
`BridgeOAuthIntrospectionCredentialStore`, which uses machine-scope DPAPI and
the exact protected ACL authority. Existing ciphertext is not replaced.

Command output contains only non-secret evidence: issuer, client ID, service
SID/state/start mode, secret path, ciphertext SHA-256, and ACL status.

## Validation

Local/synthetic focused validation for this tranche covers:

- effective Administrator + SCM identity/state proof
- failure before stdin read when privilege proof fails
- exact JSON fields and duplicate-field rejection
- bounded stdin
- create-only publication call ordering
- no `client_secret` in returned evidence
- CLI has no secret/path option surface

Focused synthetic tests: `17 passed`.

No real Windows host, SCM, DPAPI cross-identity, OAuth server, TLS listener,
or Hyper-V execution is claimed by this document.
