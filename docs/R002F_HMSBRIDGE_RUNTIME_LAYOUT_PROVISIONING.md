# R002F HMSBridge runtime layout provisioning authority

Status: `STAGED_NOT_EXECUTED`

The production writable runtime layout is frozen to:

`C:\ProgramData\HMS-GPT-VPS\Bridge\runtime`

with provision state:

`C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\provision-state.json`

Required directories:

- `db`
- `secrets`
- `locks`
- `secrets\principal-bindings`

`provision_bridge_runtime_layout()` requires the exact elevated/quiescent HMSBridge provisioning identity before and after mutation. The service must remain `NT SERVICE\HMSBridge`, `Manual`, and `Stopped`.

Each writable runtime directory uses a protected DACL owned by Builtin Administrators:

- SYSTEM: FullControl, inheritable to child files/directories
- Builtin Administrators: FullControl, inheritable
- dedicated HMSBridge service SID: Modify + Synchronize, inheritable

This is intentionally separate from the package tree, which remains RX-only for HMSBridge, and from `secrets\service-runtime`, whose existing machine-secret authority replaces inherited Modify with a protected read-only service DACL.

The provisioner rejects reparse traversal, creates only the frozen directories, performs an observer-only second ACL proof, runs `BridgeRuntimeLayout.prepare()` against the created layout, and re-proves the service identity after provisioning.

Validation before commit:
- module + focused test syntax compile: PASS;
- focused synthetic/script validation: PASS;
- repository pytest / Windows ACL execution: NOT RUN.

No real runtime proof is promoted.
