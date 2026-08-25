# R002F HMSBridge host package deployment authority

Status: `STAGED_NOT_EXECUTED`

This checkpoint closes the host-side deployment gap between an attested `hms-bridge` Windows onedir artifact and the existing SCM installer.

## Fixed host paths

- host root: `C:\ProgramData\HMS-GPT-VPS\Bridge`
- package root: `C:\ProgramData\HMS-GPT-VPS\Bridge\package`
- manifest: `C:\ProgramData\HMS-GPT-VPS\Bridge\hms-bridge.manifest.json`
- entrypoint: `C:\ProgramData\HMS-GPT-VPS\Bridge\package\hms-bridge.exe`

No caller-selected destination is accepted.

## Two-phase deployment

The package is deployed before the service exists, because `install_hms_bridge_service_authority()` requires the executable to exist and be SHA-pinned before SCM creation.

### Phase A — pre-SCM staging

`stage_bridge_package_create_only(source_root, manifest)`:

1. verifies the complete source package tree against `BridgePackageManifest`;
2. requires the entrypoint to be Windows AMD64 PE;
3. requires an elevated Administrator process and requires `HMSBridge` to be absent;
4. creates a unique staging host root beside the fixed final root;
5. copies the complete onedir package and writes the canonical manifest;
6. verifies the copied package tree and manifest bytes;
7. protects the staging root, root files, package directories and package files with protected exact SYSTEM/Admin ACLs;
8. re-proves elevated admin + absent HMSBridge;
9. atomically renames the entire staging host root to the fixed final host root with no replacement path;
10. re-verifies the complete final tree and observer-only ACL proof;
11. removes the private transaction ownership marker.

An exact already-staged final package may be observed and returned as `created=False`; conflicting or partial fixed-root content fails closed.

### Phase B — post-SCM service ACL finalization

After SCM creation, `finalize_bridge_package_service_acl(manifest)`:

1. verifies the complete staged package again;
2. proves exact elevated/quiescent HMSBridge authority (`NT SERVICE\HMSBridge`, Manual, Stopped);
3. grants the host/package tree exact protected read/execute access only to the dedicated HMSBridge service SID while retaining SYSTEM/Admin FullControl;
4. keeps root-level package metadata files admin-only;
5. re-verifies the complete package tree;
6. performs observer-only exact ACL proof;
7. re-proves the HMSBridge service SID/state.

This split avoids granting a guessed or broad principal access before the real SCM virtual-account authority exists.

## Failure cleanup

Only a unique staging root carrying the transaction's random ownership marker may be recursively removed. After atomic publication, rollback is attempted only while HMSBridge is still absent and the ownership marker remains exact.

No runtime service is started by this authority.

## Validation before commit

- module + focused test syntax compile: PASS;
- focused synthetic validation of deterministic manifest identity, elevated/absent-service preflight, admin-only versus service-read ACL script modes, and service SID binding: PASS;
- repository pytest / Windows ACL execution: not performed here.

All real production proof flags remain false.
