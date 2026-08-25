# R002F — Production Bridge service runtime lifecycle

Status: `STAGED_NOT_EXECUTED`

This checkpoint stages the long-lived `HMSBridge` runtime composition that sits behind
the Windows SCM host. It does not start the Windows service and does not claim any
real Windows/Hyper-V proof.

## Authority

`BridgeProductionServiceRuntimeConfig` pins one service SID across:

- the SCM/runtime authority;
- the machine-scope Bridge secret store reader;
- the Agent TLS private-key reader.

The machine-scope secret root must be the fixed `service-runtime` child under the
production Bridge `secrets` directory.

## Construction order

`build_bridge_production_service_runtime(...)` is fail closed:

1. prove the exact low-privilege `NT SERVICE\HMSBridge` token;
2. load the already-provisioned LocalMachine-DPAPI service secrets behind exact ACLs;
3. build `BridgeProductionDependencies`;
4. assemble the production Bridge;
5. re-prove the exact service token before publishing the runtime object.

No privileged provisioning credential is accepted by this factory.

## Runtime lifecycle

`BridgeProductionServiceRuntime.run(stop)`:

1. re-proves the strict service identity immediately before listener startup;
2. starts the private Agent TLS listener through the existing production TLS runtime;
3. builds MCP Streamable HTTP as a top-level ASGI application;
4. hosts MCP on exact loopback `127.0.0.1` with the configured MCP port;
5. uses a non-daemon uvicorn server thread with bounded startup;
6. watches both SCM stop and unexpected MCP exit;
7. requests graceful uvicorn exit on SCM stop, escalates to `force_exit` only after the
   bounded graceful wait, and fails closed if the thread remains alive;
8. always shuts down the Agent TLS listener in `finally`.

The MCP ASGI application is served directly rather than mounted into another ASGI
application, so its built-in session-manager lifespan remains authoritative.

## Remaining boundary

This checkpoint deliberately does not change the older SID-only helper inside
`agent_bridge_tls_storage.py`. The production SCM path now has strict identity gates
at the service host, secret loader, runtime factory construction, and runtime start.
A later contained remediation should supersede the compatibility helper itself.

The SCM host still reports `SERVICE_RUNNING` before `runtime.run(...)` has completed
listener startup. That lifecycle/reporting issue must be remediated before production
service activation.

## Validation

Scratch validation only:

- direct Python syntax compilation: PASS for module and focused tests;
- synthetic dependency-stub import: PASS.

Not executed here:

- repository pytest suite;
- GitHub Actions;
- real Windows SCM;
- real service SID/token proof;
- real LocalMachine-DPAPI load;
- real TLS bind;
- real MCP bind;
- real managed-guest TLS;
- authenticated Agent traffic;
- full command flow.

Therefore all production proof flags remain false, including
`authenticated_agent_transport_proven`, `full_bridge_command_flow_proven`,
`bootstrap_retired`, and `pairing_ready`.
