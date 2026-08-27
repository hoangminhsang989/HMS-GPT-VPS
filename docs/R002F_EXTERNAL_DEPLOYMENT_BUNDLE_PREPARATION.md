# R002F External Deployment Bundle Preparation

Status: `STAGED_NOT_EXECUTED`

This tranche adds a Windows-only, non-executing preparation gate for the
R002F external deployment authority bundle. It closes the remaining manual
hash-binding gap between already-built sealed manifests and the existing
bundle renderer.

## Purpose

The preparation command accepts concrete Windows authority paths, but it does
not accept caller-supplied project/Python/Git manifest SHA-256 values. Instead
it:

1. pins and validates the reviewed V2 launcher bytes;
2. pins and validates the reviewed stage-0 child bytes;
3. pins and parses the reviewed-project manifest;
4. requires its `reviewed_commit` to equal the requested commit;
5. verifies the concrete project source tree against that manifest;
6. pins and parses the Python runtime manifest and requires role
   `python-runtime`;
7. verifies the concrete Python runtime source tree;
8. pins and parses the Git runtime manifest and requires role `git-runtime`;
9. verifies the concrete Git runtime source tree;
10. calculates all three manifest SHA-256 values from the exact pinned
    canonical manifest bytes;
11. builds the existing strict deployment-bundle model;
12. publishes the canonical bundle create-only with pinned readback.

The output result contains only bundle path, bundle SHA-256, reviewed commit,
and explicit non-execution booleans.

## Existing authority reused

The implementation deliberately reuses:

- `SealedExecutionTreeManifest.from_bytes()` and
  `verify_sealed_execution_tree()`;
- `SealedRuntimeManifest.from_bytes()` and
  `verify_sealed_runtime_tree()`;
- `read_file_pinned()` and `write_bytes_create_only()`;
- `R002FExternalDeploymentAuthorityBundle`;
- the fixed reviewed launcher SHA-256
  `0f2c12973ede984b3eb55ec26284bb068b1d4f9050b1a5f629fff0ac71f863f6`;
- the fixed reviewed stage-0 SHA-256
  `3b14890a51b7d51aaac0105d1f3149a85c2c0e9b10208f25b4cc8f61130c787f`.

It does not introduce an alternate source-tree verifier, runtime-manifest
schema, or launcher authority.

## Fail-closed boundary

Preparation fails if:

- the host is not Windows;
- either managed-guest bootstrap secret environment variable is present;
- launcher/stage-0 filename or SHA-256 differs;
- any manifest is noncanonical;
- the reviewed-project manifest commit differs;
- Python/Git runtime roles are swapped or otherwise invalid;
- any source tree differs from its manifest;
- the bundle output is not a direct child of the protected authority parent;
- the bundle output aliases another deployment authority path;
- the existing deployment-bundle model rejects any path/identity relation;
- the create-only output already exists;
- pinned readback differs from canonical bundle bytes.

The bootstrap environment exclusion uses the existing
`HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME` and
`HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD` authorities. No secret value is
published.

## Usage

Run this only after the reviewed project manifest and complete Python/Git
runtime manifests already exist on the Windows qualification host.

```powershell
python scripts/prepare_r002f_external_deployment_bundle.py <all required authority arguments>
```

The command prints a compact JSON result containing the newly-created bundle
path and its SHA-256. Record/pin that SHA-256 through the external operating
procedure before rendering the execution command:

```powershell
python scripts/render_r002f_external_deployment_command.py `
  --bundle <deployment.bundle.json> `
  --bundle-sha256 <externally-pinned-sha256>
```

The preparation command intentionally does **not** render or execute the
launcher and does not create an independent trust root for its own output.

## Proof boundary

Successful bundle preparation does **not** prove any live qualification fact.
It must not set or infer:

- `hyperv_guest_proven`;
- `live_managed_guest_tls_proven`;
- `authenticated_agent_transport_proven`;
- `openai_control_plane_origin_proven`;
- `full_bridge_command_flow_proven`;
- `bootstrap_retired`;
- `pairing_ready`;
- `chatgpt_ui_origin_proven`;
- any ChatGPT OAuth/private-key-jwt proof.

The resulting bundle remains host-specific deployment authority data. Real
proof begins only after the externally-pinned launcher executes the sealed
preparation/preflight chain on the authorized Windows/Hyper-V host.
