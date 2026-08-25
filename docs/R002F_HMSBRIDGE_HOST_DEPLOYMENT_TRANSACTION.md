# R002F — HMSBridge host create-only deployment transaction

Status: `STAGED_NOT_EXECUTED`

This tranche composes the previously reviewed host-side authorities into one fail-closed first-deployment transaction. It deliberately does **not** start `HMSBridge`, does not change the service to Automatic, and does not claim live TLS, Agent authentication, command flow, bootstrap retirement, or pairing readiness.

## Frozen service identity

Windows service SIDs are derived from uppercase UTF-16LE service-name bytes, SHA-1, then five little-endian DWORD subauthorities under `S-1-5-80` (Microsoft MS-LSAT configurable translation database rule).

For `HMSBridge` the frozen expected SID is:

`S-1-5-80-3027300117-82505545-3616633165-1729693371-3881641565`

The transaction derives this value locally before SCM creation and the SCM installer later proves the actual `NT SERVICE\HMSBridge` SID is identical.

## First-deployment order

1. Validate non-secret plan fields and fixed ProgramData/TLS authorities.
2. Verify and create-only stage the complete attested `hms-bridge` onedir package.
3. Install/reconcile `HMSBridge` as a stopped/manual virtual-account SCM service using the derived exact service SID and pinned executable SHA-256.
4. Finalize exact service read/execute ACL over the package tree.
5. Provision exact writable runtime layout (`db`, `secrets`, `locks`, `principal-bindings`).
6. Compile the runtime config against the now-existing fixed runtime layout and service SID.
7. Create-only publish TLS certificate/private-key material; no listener is started.
8. Under stopped/manual identity proof, create/prove the machine-scope pairing key and host copy of the Agent device credential.
9. Provision host firewall and managed-guest trust root; still no listener is started.
10. Create-only publish protected `bridge-runtime.json`.
11. Provision the OAuth introspection client credential through the existing hardened stdin ingress using an in-memory `BytesIO` payload; no secret appears in argv/runtime JSON/log output.
12. Protected-load the OAuth credential and compare exact in-memory identity.
13. Re-load protected runtime config and final TLS material.
14. Final proof requires exact service SID, `Manual`, and `Stopped`.

## Failure semantics

The transaction is intentionally create-only, not an auto-repair loop. Each stage failure is wrapped with a stable stage name. It never deletes or overwrites already-published security authorities. Partial state remains fail-closed with the service expected to be `Manual` and `Stopped`; recovery/resume is a separate authority rather than destructive rollback hidden inside this transaction.

No stage calls `Start-Service`, `sc start`, the service dispatcher, the TLS listener start method, or the MCP server start method.

## Secret handling

The deployment request marks Agent credentials, OAuth credentials, TLS PEM material, PowerShell Direct credentials, and trust-root bytes `repr=False`. OAuth provisioning reuses the existing hardened stdin ingress through `BytesIO`; private-key publication reuses the protected pre-created-file authority. Returned transaction evidence contains identifiers/hashes only.

## Validation performed

- Python syntax compile: PASS.
- Deterministic service SID test against Microsoft `ALG` example: PASS.
- Frozen `HMSBridge` derived SID check: PASS.
- Synthetic complete transaction ordering/evidence regression: PASS.
- Secret repr exclusion regression authored.
- Stage-failure wrapping/no-continue regression authored.
- Repository pytest / Windows native transaction execution: NOT RUN in this environment.

All live qualification flags remain false until a Windows host executes the committed transaction against the exact reviewed package/config/VM authority.
