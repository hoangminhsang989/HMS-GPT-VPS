# R002F — HMSBridge LocalMachine-DPAPI secret authority

Status: `STAGED_NOT_EXECUTED`

This checkpoint introduces a new production-only secret authority for the `NT SERVICE\HMSBridge` virtual account. It does not reinterpret or migrate legacy current-user Bridge DPAPI files.

## Storage authority

Fixed root: `...\secrets\service-runtime` under an already-created Bridge secrets parent.

Allowed children are only:

- `pairing-exchange-key.service-machine.dpapi`;
- `agent-credentials\`;
- credential files named `<sha256(instance_id)>.service-machine.dpapi` inside that directory.

The root and credential directory use protected DACLs owned by Builtin Administrators with exactly SYSTEM FullControl, Administrators FullControl, and the deployment-pinned `HMSBridge` service SID ReadAndExecute. Secret files use the same owner and administrative authorities with HMSBridge Read. Reparse traversal and unknown entries fail closed.

Provisioning may reconcile these ACLs. Runtime proof uses the same observer with reconciliation disabled and requires `changed=false` before secret loading.

## Cryptographic scope

The production service stores use DPAPI `CRYPTPROTECT_LOCAL_MACHINE` so a privileged provisioning identity can create ciphertext that the same-machine virtual service account can later decrypt. Machine scope is not treated as per-service authorization: the exact filesystem ACL above remains mandatory.

A distinct pairing-key magic (`HMS-PXK-SVC-V1`) and a distinct Agent credential protection scope (`local-machine-service`) prevent legacy/current-user/guest stores from being silently reinterpreted as service production secrets.

## Dependency loader

`load_bridge_service_secret_dependencies(...)` first proves the effective process token is the exact low-privilege `NT SERVICE\HMSBridge` authority, then proves the storage ACL authority, loads the pairing exchange key, creates request/command credential resolvers, and re-proves storage before returning. An administrator/provisioning process therefore cannot use the runtime loader as a convenience path to read production secrets. OAuth verifier construction remains outside this secret-only loader and will be injected when composing the complete production Bridge dependencies.

The following remain false until real Windows qualification succeeds:

- real HMSBridge secret ACL proof;
- real LocalMachine-DPAPI cross-identity decrypt proof;
- live managed-guest TLS proof;
- authenticated Agent transport proof;
- full Bridge command flow proof;
- bootstrap retired;
- pairing ready.
