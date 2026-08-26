# R002F — HMSBridge host create-only deployment transaction

Status: `STAGED_NOT_EXECUTED`

This create-only transaction now stages every host authority required before a future HMSBridge service generation can expose local MCP through the pinned Secure MCP Tunnel. It deliberately leaves the SCM service `Manual` and `Stopped` and never starts the tunnel.

## Frozen service and tunnel authority

The frozen HMSBridge virtual-account SID remains:

`S-1-5-80-3027300117-82505545-3616633165-1729693371-3881641565`

The tunnel runtime remains pinned to OpenAI `tunnel-client` v0.0.12 and its reviewed Windows runtime archive hash. Runtime config schema v2 carries only the non-secret canonical `tunnel_<32 lowercase hex>` identifier; the restricted runtime API key is kept separately under LocalMachine DPAPI in service-secret storage.

## First-deployment order

1. Validate the request, including schema-v2 runtime config, tunnel archive path, and bounded upstream-compatible tunnel API-key characters.
2. Verify and create-only stage the attested `hms-bridge` package.
3. Install/reconcile HMSBridge as exact virtual-account SCM authority in `Manual/Stopped` state.
4. Finalize exact Bridge package read/execute ACLs.
5. Provision the fixed writable Bridge runtime layout.
6. Compile the protected production runtime configuration.
7. Verify/extract the pinned OpenAI tunnel runtime archive, publish its canonical manifest, reconcile immutable package ACLs, and prove the exact installed package.
8. Create-only publish Agent TLS material; no listener is started.
9. Re-prove elevated provisioning identity while HMSBridge remains stopped.
10. Provision the machine-scope pairing key and Agent device credential.
11. Create-once protect the restricted tunnel runtime API key with LocalMachine DPAPI.
12. Reconcile and prove the exact service-secret ACL set, then protected-load and constant-time compare the tunnel key.
13. Re-prove provisioning identity.
14. Provision host firewall and managed-guest TLS trust prerequisites; still no listener is started.
15. Create-only publish protected `bridge-runtime.json` schema v2 only after tunnel package/key authorities exist.
16. Provision and protected-load the OAuth introspection credential.
17. Re-load protected runtime config and TLS material.
18. Re-prove service-secret ACLs, tunnel-key custody, immutable tunnel package bytes/ACLs, and final `Manual/Stopped` service identity.

## Failure semantics

Every stage has a stable failure label and fails closed. The transaction does not silently delete or overwrite already-published security authorities. Partial deployment remains stopped/manual for explicit recovery.

No stage calls `Start-Service`, enters the service dispatcher, starts the Agent TLS listener, starts MCP, or launches `tunnel-client-runtime.exe`.

## Secret handling

Agent credential, OAuth client secret, TLS private-key bytes, PowerShell Direct password material, trust-root bytes, and tunnel runtime API key are excluded from request repr. The tunnel API key is not written to `bridge-runtime.json`, argv, the tunnel package manifest, or returned deployment evidence.

Returned evidence may state only readiness booleans, identifiers, and hashes. Successful staging still reports:

- `status=STAGED_NOT_EXECUTED`;
- `tunnel_package_ready=true`;
- `tunnel_api_key_ready=true`;
- `tunnel_runtime_started=false`;
- `tunnel_ready=false`;
- `pairing_ready=false`.

## Validation boundary

Focused local regression covers deterministic service SID, secret repr exclusion, stage ordering, tunnel package/key/ACL placement before config publication, upstream-compatible API-key ingress validation, final observer proofs, and no-continue failure wrapping.

Repository CI, native Windows transaction execution, real LocalMachine-DPAPI behavior, real official ZIP acquisition on the target host, real tunnel child execution, and real OpenAI/ChatGPT principal attachment remain unproven.
