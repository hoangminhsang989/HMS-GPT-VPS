# R002E CI Checkout Authority Hardening

Status: staged on `r002e-self-hosted-runner-fallback`; not yet applied to PR #11.

## Finding

The current PR workflow uses `on: pull_request` with default `actions/checkout@v4` behavior. GitHub documents that an open pull request uses `refs/pull/<number>/merge` as `GITHUB_REF`, and default checkout therefore checks out the synthetic merge commit rather than the raw pull-request head.

Run #412 was associated with PR head `1fc5ad20068444446f154f72ed44eb7ec5a0ee5f`, but no runner step executed. Therefore no checkout actually occurred. It is incorrect to treat #412 as evidence that raw head bytes were tested.

Future R002E qualification must distinguish:

- **PR head authority**: exact reviewed source commit bytes;
- **synthetic merge authority**: GitHub's temporary merge of head into base.

The required R002E matrix/package/native-SCM gate is defined against exact reviewed head bytes. If integration against a moved base is later required, that is a separate merge-integration gate.

## Candidate workflow changes

The staged `.github/workflows/ci.yml` candidate makes these changes without reducing test coverage:

1. Each checkout explicitly selects:

```yaml
ref: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}
```

2. Each job verifies `git rev-parse HEAD` equals the expected event SHA before install/test/build/qualification.
3. Each checkout sets `persist-credentials: false` because the CI jobs do not push repository changes.
4. All external `actions/*` dependencies are pinned to full immutable commit SHAs instead of movable major tags.

Resolved official action commits at this checkpoint:

- `actions/checkout`: `11d5960a326750d5838078e36cf38b85af677262` (v4 line)
- `actions/setup-python`: `a26af69be951a213d495a4c3e4e4022e16d87065` (v5 line)
- `actions/upload-artifact`: `ea165f8d65b6e75b540449e92b4886f43607fa02` (v4 line)
- `actions/download-artifact`: `d3f86a106a0bac45b974a628896c90dbdf5c8093` (v4 line)

These SHAs were resolved directly from the official `actions/*` repositories. Before any later refresh, resolve and review replacement SHAs again rather than blindly moving a pin.

## Self-hosted trust boundary

GitHub's security guidance states that pinning an action to a full-length commit SHA is the only way to use an action as an immutable release. This is especially important before running CI on a privileged self-hosted Windows/Hyper-V host.

A custom runner label is routing metadata, not authorization. The physical/self-hosted runners must remain offline until the exact candidate head and workflow have been reviewed and frozen.

## Application gate

Do not apply this staged workflow candidate to PR #11 merely to create another zero-step run while Issue #12 remains unresolved.

Once actual runner capacity is available:

1. re-read PR #11 head/base and confirm no concurrent change;
2. re-resolve the four pinned action SHAs from their official repositories;
3. compare the staged candidate workflow against then-current PR workflow;
4. apply the workflow hardening as one batched commit to the PR branch;
5. treat the resulting new commit as the new exact-head authority;
6. execute and pass the complete Linux/Windows Python matrices, package attestation and native Windows SCM qualification on that new exact head;
7. if base `main` moved, evaluate merge-integration separately rather than silently substituting the synthetic merge commit for exact-head evidence.

## Existing proof boundary

This workflow hardening does not prove the managed guest or Bridge command flow. The following remain false until separately proven:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`
