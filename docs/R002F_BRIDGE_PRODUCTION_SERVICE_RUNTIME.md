# R002F — Production Bridge service runtime lifecycle

Status: `STAGED_NOT_EXECUTED`

This authority stages the long-lived `HMSBridge` runtime behind the Windows SCM host. It now composes the private Agent TLS listener, loopback MCP server, and supervised OpenAI tunnel-client runtime. It does not claim a real Windows service start or a real OpenAI tunnel attachment.

## Composite authority

`BridgeProductionServiceRuntimeConfig` binds one exact `NT SERVICE\HMSBridge` SID across:

- SCM/runtime identity;
- machine-scope Bridge secret reader;
- Agent TLS private-key reader;
- Secure MCP Tunnel supervisor;
- durable non-secret `tunnel_id` loaded from protected `bridge-runtime.json` schema v2.

The production MCP endpoint remains exact loopback `127.0.0.1:8765/mcp`. The tunnel package remains outside the service-writable runtime tree under the fixed immutable package authority `C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12`.

## Construction order

`build_bridge_production_service_runtime(...)` remains fail closed:

1. prove the exact low-privilege HMSBridge token;
2. load already-provisioned LocalMachine-DPAPI service dependencies behind exact ACLs;
3. assemble the production Bridge and local MCP authority;
4. re-prove the service token;
5. publish a runtime object whose tunnel supervisor is still unstarted.

No privileged provisioning credential, tunnel API key, config path, or tunnel ID is accepted on argv.

## Startup and SCM readiness

`start(stop)` now owns the complete readiness boundary:

1. re-prove HMSBridge runtime identity;
2. start the exact private Agent TLS listener;
3. start MCP Streamable HTTP on exact loopback `127.0.0.1:8765`;
4. require the MCP server thread to reach bounded startup and remain alive;
5. construct `SecureMcpTunnelRuntime` from protected service authority;
6. start the pinned `tunnel-client-runtime.exe` child;
7. require a fresh canonical loopback health URL handoff and accepted `/readyz` response;
8. re-check TLS/MCP and call `tunnel.assert_healthy()`;
9. re-prove service identity;
10. return `True` only then, allowing the SCM host to publish `SERVICE_RUNNING`.

A pre-existing SCM stop returns `False` without opening listeners. Any startup failure runs bounded reverse cleanup and never converts partial readiness into SCM readiness.

## Steady-state health

`wait(stop)` continues checking:

- MCP thread liveness and stored MCP startup/runtime errors;
- exact Agent TLS bind authority;
- Secure MCP Tunnel child liveness and fresh `/readyz` through `assert_healthy()` on a bounded cadence.

A tunnel child exit, unreachable tunnel health endpoint, or degraded readiness fails HMSBridge closed. The child is not blindly restarted inside the service process; failure bubbles to the existing bounded SCM recovery policy.

## Shutdown order

Shutdown is idempotent and intentionally removes remote ingress first:

1. Secure MCP Tunnel;
2. local MCP server, graceful then forced only after bounded wait;
3. Agent TLS listener.

A failure in an earlier shutdown stage does not skip later cleanup; the first failure is surfaced after owned resources have been given their cleanup attempt.

## Validation boundary

Dependency-isolated local regression covers composite ordering, rollback, tunnel health loss, MCP/TLS liveness, fixed port/tunnel ID validation, and shutdown ordering. The Secure MCP Tunnel focused suite separately covers process, package, health handoff, secret-environment scrubbing, and one-shot `assert_healthy()` behavior.

This is not GitHub CI, native Windows SCM proof, a real `tunnel-client-runtime.exe` run, or a real OpenAI/ChatGPT principal flow. Project status remains `STAGED_NOT_EXECUTED`.
