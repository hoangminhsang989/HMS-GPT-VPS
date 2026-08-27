# R002F External Runtime Manifest Approval Gate

Status: `STAGED_NOT_EXECUTED`.

This descendant closes the remaining runtime-manifest self-attestation gap in the
external deployment bundle preparation path.

## Problem

The manifest-authoring tranche deliberately treats Python and Git runtime
manifests as observations:

- `external_approval_required=true`
- `external_approval_self_proven=false`

Before this remediation, bundle preparation accepted canonical runtime manifest
files and verified source trees, but it computed each runtime manifest SHA-256
inside the same preparation process. That did not prove the runtime manifest
digest had been independently reviewed or approved before deployment.

## New external authority

Bundle preparation now requires two additional inputs:

- `--python-manifest-sha256 <externally-approved-64-lowercase-hex>`
- `--git-manifest-sha256 <externally-approved-64-lowercase-hex>`

These values must come from deployment/review authority outside the preparation
process. The preparation code does not discover or promote them from local
runtime files.

For each runtime manifest, preparation performs the following order:

1. canonicalize the externally supplied SHA-256 authority;
2. pinned-read the exact manifest bytes once;
3. compare SHA-256 of those exact bytes to the external authority;
4. parse the same in-memory bytes;
5. require canonical byte form;
6. require exact runtime role (`python-runtime` or `git-runtime`);
7. verify the concrete runtime source tree against that same parsed manifest;
8. bind the externally approved digest into the deployment bundle.

The manifest path is not re-read between external digest validation, source-tree
verification, and bundle construction. A later path replacement therefore
cannot substitute different manifest bytes into the bundle authority.

## Project manifest boundary

The project manifest remains independently rebound to the exact reviewed Git
commit via the existing Git-tree authority. This tranche does not weaken or
replace that boundary.

## Fail-closed behavior

Bundle publication is blocked before write when:

- Python or Git external manifest SHA-256 is missing/noncanonical;
- observed manifest bytes differ from the external digest;
- runtime role is swapped;
- canonical manifest bytes are malformed;
- source tree differs despite a correct approved manifest digest;
- any prior project/Git/launcher/stage-0/create-only authority fails.

No bootstrap secret is accepted or stored.

## Updated invocation

The preparation CLI adds:

```powershell
--python-manifest-sha256 <externally-approved-python-manifest-sha256> `
--git-manifest-sha256 <externally-approved-git-manifest-sha256>
```

The runtime authoring CLI may print observed SHA-256 values for review, but those
observations are not self-approved. Deployment authority must explicitly pin the
two values before bundle preparation.

## Proof boundary

This is still preparation-only and `STAGED_NOT_EXECUTED`.

It does not start the launcher, Hyper-V, HMSBridge, HMSAgent or the tunnel. It
does not prove Windows execution, ChatGPT UI/OAuth provenance, bootstrap
retirement, pairing readiness or full Bridge command flow.

All live production proof booleans remain false until separate real execution
evidence exists.
