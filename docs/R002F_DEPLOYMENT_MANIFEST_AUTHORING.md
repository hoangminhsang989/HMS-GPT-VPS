# R002F Deployment Manifest Authoring Boundary

Status: `STAGED_NOT_EXECUTED`.

This authoring module produces **manifest observations only**. No manifest hash
printed by the same Python process is allowed to self-promote into external
deployment authority.

## Project manifest correction

The legacy `project` command still performs useful defense-in-depth checks:

- exact clean checkout checks around Git-tree collection;
- exact `git ls-tree -r -z --full-tree` parsing;
- project export namespace/byte verification;
- Git blob SHA-1 binding for every project file;
- create-only canonical manifest publication with pinned readback.

However, fresh review found that this path pins only the reviewed `git.exe` bytes.
It does **not** independently seal/prove the complete Git DLL/dependency runtime
closure before executing Git. Therefore the generated project-manifest digest is
an **observation candidate**, not a root of trust.

The project result now always states:

- `external_approval_required=true`
- `external_approval_self_proven=false`

The old classification `external_approval_required=false` is rejected and must
not be used for production qualification.

## Python and Git runtime manifests

The `python-runtime` and `git-runtime` commands remain observation-only. They
verify complete source namespace/bytes using `SealedRuntimeManifest` and publish
canonical create-only manifests, but also always state:

- `external_approval_required=true`
- `external_approval_self_proven=false`

## Production authority path

For production qualification, use an independent external authority that does
not execute the unsealed Python/Git preparation toolchain before stage-0. The
current frozen architecture is:

1. external PowerShell/.NET authority derives/reviews the exact project manifest
   from GitHub committed object bytes and observes complete Python/Git closures;
2. an independent review pins the project/Python/Git manifest SHA-256 values;
3. bundle + rendered-command candidates are produced and independently pinned;
4. the target-side execution handoff verifies/pins exact approved bytes;
5. only OS-backed Windows PowerShell starts launcher -> stage-0;
6. stage-0 creates/seals project/Python/Git roots before sealed Python preflight.

The legacy Python project/Git checks may remain as defense-in-depth evidence, but
their output cannot by itself satisfy external approval.

## Commands

```powershell
python scripts/author_r002f_deployment_manifests.py project `
  --project-source-root <export-tree> `
  --repo-evidence-root <exact-clean-checkout> `
  --reviewed-commit <40-hex> `
  --git-executable <absolute-git.exe> `
  --git-executable-sha256 <external-sha256> `
  --output <project.manifest.json>
```

```powershell
python scripts/author_r002f_deployment_manifests.py python-runtime `
  --runtime-source-root <python-closure> `
  --entrypoint <relative-python.exe> `
  --output <python.manifest.json>
```

```powershell
python scripts/author_r002f_deployment_manifests.py git-runtime `
  --runtime-source-root <git-closure> `
  --entrypoint <relative-git.exe> `
  --output <git.manifest.json>
```

All three commands are observation/preparation only. They do not start Hyper-V,
HMSBridge, HMSAgent, the tunnel, or any production qualification flow. All live
proof booleans remain false.
