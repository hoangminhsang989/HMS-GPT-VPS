# R002F — HMSBridge SCM readiness ordering

Status: `STAGED_NOT_EXECUTED`

This authority supersedes earlier TLS+MCP-only readiness descriptions. HMSBridge SCM readiness now includes the supervised Secure MCP Tunnel.

## Canonical ordering

The runtime contract remains split into `start`, `wait`, and `shutdown`.

`start(stop) -> bool`:

1. strict `NT SERVICE\HMSBridge` identity proof;
2. Agent TLS exact bind;
3. loopback MCP exact bind on `127.0.0.1:8765` and bounded server startup;
4. Secure MCP Tunnel child start from the immutable pinned package;
5. fresh health URL handoff and accepted `/readyz`;
6. fresh local TLS/MCP check plus tunnel `assert_healthy()`;
7. final service identity proof;
8. return `True` only when the composite runtime is ready.

`wait(stop)` fails closed on MCP exit/error, TLS authority loss, tunnel child exit, unreachable tunnel health, or degraded `/readyz`.

`shutdown()` removes ingress in this order:

`tunnel -> MCP -> Agent TLS`

`run(stop)` remains a compatibility wrapper around `start -> wait -> shutdown`; the Windows SCM host owns the status transitions.

## SCM status authority

The host ordering remains:

`START_PENDING -> runtime.start() -> RUNNING -> runtime.wait() -> STOP_PENDING -> runtime.shutdown() -> STOPPED`

Therefore `SERVICE_RUNNING` must never be published from TLS+MCP readiness alone. If tunnel startup fails or stop wins before composite readiness, the service never reaches `RUNNING`.

## Restart authority

The tunnel supervisor deliberately contains no blind child restart loop. Runtime health failure escapes the HMSBridge service generation and delegates recovery to the existing bounded SCM failure-action authority. A fresh generation must re-prove service identity, protected secrets, immutable package bytes/ACLs, and tunnel health.

## Validation boundary

Focused local dependency-isolated tests cover composite startup ordering, pre-stop behavior, tunnel-start rollback, steady tunnel loss, reverse shutdown ordering, and fixed MCP/tunnel authority. This is not repository CI or native Windows execution.

Still unproven: real SCM execution, real LocalMachine-DPAPI tunnel-key use, real `tunnel-client-runtime.exe`, real OpenAI tunnel attachment, real ChatGPT/MCP principal flow, full command flow, bootstrap retirement, and pairing readiness.
