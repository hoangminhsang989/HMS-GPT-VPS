# R002F external deployment authority bundle

Status: `STAGED_NOT_EXECUTED`.

This tranche consolidates the already-reviewed external sealed-preparation authorities into one canonical, data-only deployment bundle. It does not create a new runtime-closure format and it does not move the root of trust away from the external OS-trusted launcher boundary.

## Reviewed execution authorities

The bundle hard-pins the currently approved launcher V2 SHA-256:

`0f2c12973ede984b3eb55ec26284bb068b1d4f9050b1a5f629fff0ac71f863f6`

and the reviewed child stage-0 SHA-256:

`3b14890a51b7d51aaac0105d1f3149a85c2c0e9b10208f25b4cc8f61130c787f`

The reviewed commit remains an explicit bundle input. This avoids a self-referential Git commit/hash contract: after an exact source revision is selected, the deployment authority creates a bundle for that revision and externally pins the bundle SHA-256.

## Bundle contents

The canonical JSON binds:

- exact reviewed Git commit;
- protected `authority_parent`;
- launcher and stage-0 absolute paths plus reviewed SHA-256 values;
- project source root, existing reviewed project manifest path/hash, and sealed execution destination root;
- Python source root, existing complete runtime manifest path/hash, and sealed destination root;
- Git source root, existing complete runtime manifest path/hash, and sealed destination root;
- mutable `repo_evidence_root`;
- create-only preflight, stage-0 and launcher proof paths;
- explicit one-shot/preflight authority paths, challenge commit/workspace/hash, bounded reconcile count and bounded timeouts.

It contains no bootstrap username/password and no OAuth/private material. It contains no per-file closure list because the existing project/runtime manifests remain the closure authorities.

## Canonicalization and validation

The bundle parser is fail-closed:

- strict UTF-8 JSON;
- duplicate fields rejected;
- NaN/Infinity rejected;
- exact object schemas and exact scalar types;
- canonical lowercase SHA-1/SHA-256;
- canonical absolute Windows paths;
- reviewed launcher/stage-0 hashes must match the frozen V2 authority;
- launcher, stage-0, manifests, destinations and proofs must obey the same direct-child authority layout used by the reviewed launcher/stage-0;
- sealed destinations must be distinct and non-nested;
- mutable/source/evidence roots must remain separate from the protected authority parent and sealed destinations;
- preflight limits are explicit and finite.

`to_bytes()` is deterministic canonical JSON and `sha256` is the exact digest that the deployment operator can record outside the process.

## Render-only helper

`scripts/render_r002f_external_deployment_command.py` is an operator convenience only. It:

1. requires both the bundle path and externally supplied bundle SHA-256;
2. rejects non-canonical bundle bytes;
3. renders one Windows PowerShell command;
4. never launches Hyper-V, HMSBridge, the tunnel, or the qualification chain.

The rendered command itself performs the existing external launcher boundary: it opens the exact launcher with `FileShare.Read`, verifies the reviewed launcher SHA-256 while holding that handle, resolves Windows PowerShell from `[Environment]::SystemDirectory`, starts launcher V2 with only the bundle-bound arguments, keeps the launcher handle open for the child lifetime, and returns the child exit code.

The renderer is **not** itself the production root of trust. The operator/deployment authority must review/pin the canonical bundle digest and execute the rendered command in an OS-trusted PowerShell context.

## Proof boundary

This tranche may make the real Windows gate reproducible and low-manual, but it does not prove that the command has run. It does not set any of the following:

- `hyperv_guest_proven`;
- `full_bridge_command_flow_proven`;
- `chatgpt_ui_origin_proven`;
- `chatgpt_app_oauth_client_proven`;
- `bootstrap_retired`;
- `pairing_ready`.

Real Windows execution and proof collection remain separate.
