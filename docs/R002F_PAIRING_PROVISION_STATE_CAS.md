# R002F Pairing Provision-State CAS Authority

Status: **STAGED_NOT_EXECUTED**

Branch: `r002f-pairing-readiness-runtime`
Parent commit: `bc3e8976a2f98135918340832eb1422edbc29871`

## Authority

The pairing lifecycle now has two different durable commit owners instead of a
generic `paired=true` shortcut.

### Link publication checkpoint

`PairingReadinessRuntime.issue()` and crash-recovery
`current_pairing_link()` may commit only:

`INSTALL_SECRETS_CLEARED -> PAIRING_PENDING`

The ordering is fail-closed:

1. fresh authenticated Agent presence;
2. encrypted recoverable pairing lease;
3. exact digest-only PairingStore record;
4. immutable readback verification;
5. compare-and-swap to `PAIRING_PENDING`;
6. only then return the raw copyable link.

A crash after lease or record publication is repaired by the next issuance/read
under the same pairing authority lock. A raw link is never intentionally
released while durable provisioning state is still
`INSTALL_SECRETS_CLEARED`.

### READY checkpoint

A consumed pairing record is not enough to authorize `READY`.

Production assembly uses
`ProvisionStateBoundPrincipalPairingService`, which performs:

1. authenticated principal validation;
2. pairing exchange or exact exchange recovery;
3. durable encrypted `PrincipalSessionBinding` publication/readback;
4. fresh Agent-presence and consumed-pairing revalidation;
5. compare-and-swap `PAIRING_PENDING -> READY` with reason
   `principal_binding_published`.

If the process crashes after durable binding publication but before step 5,
retrying the same principal first recovers the exact binding and then completes
the READY CAS. A failed pairing call cannot reach the CAS.

## Legacy bypass removal

`ProvisioningOrchestrator.reconcile()` no longer treats `paired=true` as READY
authority. From `PAIRING_PENDING` it returns
`WAIT_FOR_PRINCIPAL_BINDING` without advancing state.

`ProvisioningOrchestrator.mark_ready()` is intentionally fail-closed and raises
`NotImplementedError`; production READY authority belongs only to the
principal-binding path.

This prevents a durable consumed pairing record from being mistaken for proof
that the authenticated OpenAI/MCP principal has a recoverable control-session
binding.

## Concurrency

Pairing issuance and crash-recovery link retrieval share
`exclusive_authority_lock`. Provision-state changes remain exact
`transition_checked()` CAS operations. If another exact reconciler wins the same
CAS, the pairing runtime accepts only the expected target checkpoint for the
same instance; any other state drift fails closed.

## Validation in this staging tranche

Synthetic/local checks performed while authoring this revision:

- pairing issuance/recovery CAS harness: PASS;
- unconsumed pairing cannot commit READY: PASS;
- crash-interrupted record publication repairs `PAIRING_PENDING`: PASS;
- generic orchestrator paired-observation READY bypass: blocked;
- legacy `mark_ready()` shortcut: blocked;
- production principal wrapper ordering: PASS;
- source/test syntax compilation: PASS.

These are synthetic checks only. They are **not** evidence of a real Windows
SCM run, DPAPI credential publication, OAuth principal, Secure MCP Tunnel,
managed Hyper-V guest, or end-to-end ChatGPT control session.

## Production claims remain false

- `real_pairing_link_ipc_proven=false`
- `real_openai_principal_pairing_proven=false`
- `real_principal_binding_ready_cas_proven=false`
- `full_bridge_command_flow_proven=false`
- `pairing_ready=false`
- `bootstrap_retired=false`

The next live qualification must use the real principal supplied by the
OpenAI/MCP authentication boundary. A synthetic/test principal must never
consume the one-time production pairing grant.
