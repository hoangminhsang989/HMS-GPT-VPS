# R002F HMSBridge runtime-config create-only publication authority

Status: `STAGED_NOT_EXECUTED`

This checkpoint closes the missing privileged publication path for the fixed HMSBridge runtime config:

`C:\ProgramData\HMS-GPT-VPS\Bridge\bridge-runtime.json`

## Authority

`bridge_service_provisioning_identity.py` is now the shared privileged staging identity gate. It requires:

- an effective elevated Administrator token;
- the process must not be `NT SERVICE\HMSBridge`;
- exactly one SCM service named `HMSBridge`;
- service account exactly `NT SERVICE\HMSBridge`;
- service start mode `Manual`;
- service state `Stopped`;
- a canonical `S-1-5-80-...` service SID.

The existing OAuth provisioning identity module remains as a compatibility facade over this shared gate.

## Publication

`publish_bridge_service_runtime_config_create_only()`:

1. validates the full `BridgeServiceRuntimeConfig`;
2. canonicalizes it to deterministic UTF-8 JSON and pins SHA-256;
3. proves the privileged/quiescent HMSBridge staging identity;
4. runs a fixed-path PowerShell transaction;
5. rejects any pre-existing final config — no replacement/update mode exists;
6. creates/protects the Bridge root with a protected exact DACL;
7. writes a unique temporary file with `FileMode.CreateNew`, flushes it, and proves its SHA-256;
8. protects the temporary file with the exact service-reader DACL;
9. re-proves the service is still `Manual` and `Stopped`;
10. moves the temporary file to the fixed final path without replacement;
11. proves final SHA-256, non-reparse identity, exact ACL, and stopped SCM state;
12. independently re-runs the existing observer-only config-storage proof;
13. reloads through the existing protected ACL/SHA loader;
14. re-proves the privileged/quiescent SCM identity after publication.

A failed transaction removes only its own temporary file. If failure occurs after publication, cleanup removes the final file only when it is still the exact expected SHA-256 under a stopped/manual HMSBridge and the path is not redirected.

## Exact ACL

Bridge root:

- `SYSTEM`: FullControl
- `Builtin Administrators`: FullControl
- `NT SERVICE\HMSBridge`: ReadAndExecute + Synchronize

Runtime config file:

- `SYSTEM`: FullControl
- `Builtin Administrators`: FullControl
- `NT SERVICE\HMSBridge`: Read + Synchronize

Both DACLs are protected and non-inherited; owner is Builtin Administrators.

## Validation performed before commit

- Python syntax compile: PASS.
- Focused synthetic validation of shared identity, deterministic canonical bytes, create-only/no-replace script semantics, path pinning, publication ordering, protected reload, and SHA-drift rejection: PASS.
- Repository pytest / native Windows execution: not performed in this environment.

No real Windows proof is claimed. Pairing readiness remains false.
