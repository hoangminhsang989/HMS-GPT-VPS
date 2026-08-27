# R002F Deployment Manifest Authoring Boundary

Status: `STAGED_NOT_EXECUTED`.

This tranche supplies the missing authoring boundary for the sealed deployment
manifests without allowing the authoring process to self-promote runtime bytes
into external authority.

## Reviewed project manifest

The `project` command accepts separate authorities:

- `repo_evidence_root`: exact clean Git checkout used only for Git evidence;
- `project_source_root`: exported project tree without `.git`;
- reviewed 40-hex commit;
- absolute reviewed Git executable;
- externally approved Git executable SHA-256.

The command validates the checkout, derives the exact `git ls-tree -r -z
--full-tree` path/blob mapping through the existing reviewed Git-tree authority,
re-validates the checkout, builds the project manifest against the separate
export tree, verifies that tree, then publishes the canonical manifest
create-only with pinned readback.

The project manifest is therefore rooted in the reviewed Git commit rather than
in whatever files happen to exist in the export directory.

## Python and Git runtime manifests

The `python-runtime` and `git-runtime` commands deliberately produce
**observation manifests only**.

They verify the complete source namespace and bytes using the existing
`SealedRuntimeManifest` builder/verifier and publish canonical create-only
manifests, but the result always states:

- `external_approval_required=true`
- `external_approval_self_proven=false`

A later deployment gate must receive the manifest SHA-256 from an independent
deployment/review authority. Merely generating a runtime manifest and then
trusting the hash printed by the same process is not sufficient provenance.

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

No command starts Hyper-V, HMSBridge, HMSAgent, the tunnel, or any production
qualification flow. All live proof booleans remain false.
