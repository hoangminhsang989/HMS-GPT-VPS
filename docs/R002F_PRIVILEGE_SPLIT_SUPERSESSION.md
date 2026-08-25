# R002F — Privilege split supersession for production TLS

Status: `STAGED_NOT_EXECUTED`

This checkpoint supersedes the earlier single-process production TLS orchestration from commit `fcba547d32e578c8b3bc10292880bc3ffe91edfe`.

## Why the split is required

The long-lived `HMSBridge` process is intended to run under one dedicated `NT SERVICE\HMSBridge` virtual service identity with read-only access to the production private key. PowerShell Direct, however, requires the host caller to be a Hyper-V administrator. Firewall reconciliation and guest trust-root publication are also privileged provisioning work. Giving those privileges to the long-lived Bridge service would defeat the service-SID/private-key isolation boundary.

## Canonical three-phase authority

### 1. Privileged provisioning

`provision_agent_bridge_production_tls_prerequisites(...)` may run only in the privileged provisioning/controller context. It:

- reconciles exact private-key storage ACL authority;
- preflights the pinned certificate/private-key pair;
- reconciles the exact Windows Firewall rule;
- installs/re-proves the pinned root CA in the exact VMId-bound guest;
- never starts or owns the production TLS listener;
- never claims live guest TLS or any later pairing proof.

### 2. Low-privilege HMSBridge service runtime

`start_agent_bridge_production_tls(boundary, config)` accepts no guest credential and no trust-root payload. It:

- proves the inherited process token is the exact configured dedicated service SID;
- requires private-key storage to already be converged (`changed=false`);
- loads only the pinned TLS material;
- binds the exact private listener;
- performs no firewall mutation, PowerShell Direct call, guest mutation, or live guest qualification.

### 3. Privileged live qualification

`qualify_agent_bridge_production_tls(...)` runs outside the service process. It:

- re-proves/reconciles the exact firewall authority;
- re-proves the pinned guest trust root;
- performs the VMId-bound trusted TLS handshake from guest to the already-running listener;
- pins the observed leaf certificate identity;
- still leaves authenticated Agent transport, full command flow, bootstrap retirement, and pairing readiness false.

## Validation boundary

Focused scratch validation after the split: 26/26 tests PASS using dependency stubs; direct Python syntax compilation PASS. This does not substitute for the repository suite, GitHub Actions, or real Windows/Hyper-V execution.

The following remain false until later real qualification succeeds:

- `authenticated_agent_transport_proven`
- `full_bridge_command_flow_proven`
- `bootstrap_retired`
- `pairing_ready`

PR #11 remains outside this promotion and must not be merged from this checkpoint.
