# R002F — HMSBridge SCM readiness ordering

Status: `STAGED_NOT_EXECUTED`

This checkpoint supersedes the earlier SCM lifecycle ordering in
`f393953de4ca4fd22378e8c98d20f5a23da0d5f8` and the production runtime lifecycle
staged in `bbe62ed985214faf0ba68a96306580b885c10ec6`.

## Why this checkpoint is required

The previous `HmsBridgeWindowsServiceHost` published `SERVICE_RUNNING` before
`BridgeProductionServiceRuntime.run(...)` had started and proved the Agent TLS
listener and loopback MCP server. That allowed SCM-visible readiness to get ahead
of actual runtime readiness.

The production runtime also uses `uvicorn.Server` for controllable ASGI shutdown,
so the `bridge` optional dependency must include `uvicorn`.

## Canonical SCM ordering

The service runtime contract is now split into:

1. `start(stop) -> bool`
   - performs strict `NT SERVICE\\HMSBridge` token proof;
   - starts the exact Agent TLS listener;
   - starts loopback MCP on `127.0.0.1`;
   - waits for MCP server startup;
   - re-proves TLS bind authority and strict service identity;
   - returns `True` only after all readiness gates pass;
   - returns `False` if SCM stop wins before readiness.

2. `wait(stop)`
   - is entered only after `start(...)` returned `True`;
   - fails closed if MCP exits or the TLS listener loses exact bind authority;
   - returns only after the SCM stop event is set.

3. `shutdown()`
   - is idempotent;
   - stops MCP first using bounded graceful/forced exit;
   - always closes the Agent TLS runtime;
   - never leaves TLS running because MCP shutdown failed.

`run(stop)` remains only as a compatibility wrapper around
`start -> wait -> shutdown`. The Windows SCM host no longer uses it.

The SCM host now follows:

`START_PENDING -> runtime.start() -> RUNNING -> runtime.wait() -> STOP_PENDING -> runtime.shutdown() -> STOPPED`

If stop wins during startup, `SERVICE_RUNNING` is never published. Runtime
startup failures also transition through `STOP_PENDING` before cleanup when
the service status channel remains available.

## Failure-code authority

- identity proof: `110`
- runtime construction: `120`
- runtime startup/readiness: `125`
- runtime execution/health: `130`
- runtime shutdown: `140`
- host lifecycle/status channel: `190`

## Dependency authority

`pyproject.toml` now requires `uvicorn>=0.30,<1` in the `bridge` optional
dependency set alongside `mcp>=2,<3`.

## Validation boundary

Scratch/synthetic validation performed before publication:

- updated Windows service-host focused suite: 4/4 PASS;
- production runtime start/wait/shutdown synthetic suite: 2/2 PASS;
- direct Python syntax compilation for the updated host, runtime, and focused
  test source: PASS.

This is not repository pytest, GitHub Actions, or real Windows/Hyper-V execution.

The following remain false until later real qualification succeeds:

- real-host HMSBridge SCM execution
- real-host Agent TLS listener proof
- real loopback MCP startup proof
- authenticated Agent transport proof
- full Bridge command-flow proof
- bootstrap retirement
- pairing readiness

PR #11 remains outside this promotion.
