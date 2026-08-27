# R002F sealed execution tree substrate

Status: `STAGED_NOT_EXECUTED`.

This tranche adds only the trust substrate needed to remove mutable-checkout execution from the R002F production qualification path. It does not yet wire preflight or the one-shot coordinator to the sealed tree, so no Windows/Hyper-V execution is authorized.

## New authority

`r002f_sealed_execution_manifest.py` defines a complete reviewed-project tree manifest. The builder requires an externally reviewed `path -> Git blob SHA-1` mapping plus the reviewed commit; it never derives those two authorities from the mutable execution directory itself. Every file is rebound by exact path/casing, size, SHA-256 and recomputed Git blob SHA-1. The exact implied directory namespace is also bound, so extra empty directories fail closed. Empty tracked files are supported.

`r002f_sealed_execution_acl.py` defines an exact protected Windows ACL contract for a prepared execution tree. Only SYSTEM and Administrators receive `ReadAndExecute`/`Synchronize`; there is no write/delete/full-control grant in the sealed tree. ACL reconciliation is preparation-only and processes deepest children before the root. Runtime proof must be read-only with `changed=false`.

Both layers reject links/reparse points, extra/missing entries, duplicate/case-colliding paths and type-coerced evidence.

## Deliberately still blocked

The current reviewed preflight and one-shot runner still import/execute from `repo_root/src` and `repo_root/scripts`; they are not changed by this tranche. The Python runtime closure is also still unsealed. A valid successor must:

1. prepare `execution_root` outside the mutable checkout from the exact reviewed Git-tree mapping;
2. build/verify the complete manifest;
3. reconcile exact read-only ACLs once, then re-prove them without mutation;
4. run every project import and child qualification script from `execution_root`, never the mutable checkout;
5. apply an equivalent complete-tree + sealed ACL authority to the Python runtime closure (or eliminate mutable DLL/dependency search paths);
6. resolve native PowerShell from OS-backed System32 authority;
7. run fresh committed-byte review before any real Windows/Hyper-V execution.

All live project proof booleans remain false.
