# R002F Production Bridge Assembly Authority

Status: `STAGED_NOT_EXECUTED`

This tranche composes the previously hardened R002F primitives into one Bridge-side production graph without creating a second control protocol or executing guest actions on the Windows host.

## Composition authority

`BridgeProductionConfig` binds one managed `instance_id`, the existing R002E `provision_state_path`, the canonical copied-link `bridge_base_url`, and the authenticated MCP resource configuration.

`BridgeProductionDependencies` is intentionally narrow and must be supplied by the deployment boundary:

- `PairingExchangeKey`;
- request credential resolver for `(instance_id, device_id)`;
- command credential resolver for `instance_id`;
- deployment OAuth `TokenVerifier`.

The assembly does not invent, generate, log, or persist those authorities.

## Runtime layout

The runtime root must already exist and must contain these fixed directories:

- `db/`
- `secrets/`
- `secrets/principal-bindings/`
- `locks/`

The production assembly does not create those security directories. It rejects link/reparse redirects and pins the root identity while checking the layout. A separate installer/bootstrap tranche owns creation and ACL qualification of this layout.

Fixed Bridge authorities under that root are:

- `db/pairing-control.sqlite3` — shared `PairingStore` + `ControlSessionStore` authority;
- `db/agent-presence.sqlite3` — authenticated Agent presence;
- `db/agent-commands.sqlite3` — durable Bridge→Agent command/result queue;
- `db/control-idempotency.sqlite3` — idempotency + atomic principal dispatch binding;
- `secrets/pairing-link.dpapi` — recoverable raw one-time pairing link;
- `secrets/principal-bindings/` — per-principal/per-instance encrypted session bindings;
- `locks/pairing-issuance.lock`;
- `locks/principal-pairing.lock`.

The R002E provisioning state remains external authority. R002F receives its exact path and never creates an independent provisioning state.

## Exact shared-object wiring

The assembly requires and constructs these identity relationships:

- `PairingReadinessRuntime.pairing_store is PairingSessionExchange.pairing_store`;
- `PairingReadinessRuntime.presence_reader is AgentBridgeService.registry`;
- `PairingSessionExchange.session_store is ControlGateway.session_store`;
- `PrincipalPairingService` shares the exact readiness/exchange objects;
- `PrincipalDispatchIntentStore` shares the exact `IdempotencyStore` used by `ControlGateway`;
- `PrincipalAgentControlService` shares the exact principal-pairing, gateway and Agent-Bridge objects;
- the MCP server is built only over that principal-bound façade.

Thus MCP `pair_vps/read_file/write_file` cannot silently route to a host-local executor or an unrelated pairing/session database.

## MCP deployment boundary

`BridgeProductionAssembly.run_mcp()` delegates to the existing authenticated MCP adapter. The adapter remains hard-bound to `127.0.0.1` Streamable HTTP and expects a deployment-supplied OAuth verifier. Secure MCP Tunnel / ChatGPT connection is a later deployment qualification step; this tranche does not claim a live tunnel or ChatGPT command flow.

## Security boundaries retained

- raw pairing/session/OAuth/device credentials are never tool outputs;
- `workspace.write` remains create-only through the MCP tool;
- replace/destructive writes still require a future explicit approval flow;
- Agent actions are enqueued to the outbound guest Agent and are never executed by this Bridge assembly on the host;
- pairing readiness still requires R002E install-secret cleanup and fresh authenticated Agent presence;
- production layout preparation is fail-closed and non-creating.

## Regression staged

`tests/test_r002f_bridge_production_assembly.py` checks:

- missing fixed runtime directories are rejected and not auto-created;
- redirected principal-binding authority is rejected;
- the exact shared-object graph is preserved;
- Bridge databases are created only inside the prequalified `db/` directory;
- DPAPI pairing-link secret is not created merely by assembly construction;
- redirected R002E provision-state authority is rejected;
- fixed runtime path names remain deterministic.

## Explicit non-claims

This tranche does **not** prove:

- GitHub Actions / pytest execution;
- real Windows DPAPI binding persistence;
- real managed Hyper-V Agent presence;
- Secure MCP Tunnel connectivity;
- live ChatGPT OAuth identity;
- full Bridge→Agent command completion;
- provisioning advancement to `PAIRING_PENDING` or `READY`.

Project-level proof flags therefore remain false until the corresponding real qualification gates pass.
