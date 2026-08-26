# R002F — Secure MCP Tunnel supervised runtime authority

## Status

`STAGED_NOT_EXECUTED`

This tranche extends the existing Secure MCP Tunnel package/credential/launch-spec authority with fail-closed package acquisition, exact ZIP extraction, immutable installed-package proof, child-process supervision, health URL handoff, `/readyz` gating, bounded shutdown, and crash/restart semantics.

It still does **not** claim a live Windows execution, a live OpenAI tunnel, an authenticated ChatGPT/OpenAI principal, or an end-to-end MCP command.

## Upstream runtime behavior verified for v0.0.12

The official runtime-only binary supports:

- `tunnel-client-runtime.exe run`;
- `--health.listen-addr 127.0.0.1:0` for a loopback ephemeral health port;
- `--health.url-file <path>` to publish the actual health base URL after bind;
- `--mcp.startup-wait-timeout <duration>` to keep the MCP startup probe pending while a local listener becomes available;
- `/healthz`, `/readyz`, and `/metrics` on the runtime health listener.

For v0.0.12, `/readyz` returns `503` while runtime dependencies or the MCP startup probe are pending/failed and returns `200` with a `ready...` text body only when the runtime considers itself ready. An MCP initialize response that requires authentication is an upstream-supported ready form; an arbitrary MCP failure is not.

The upstream release workflow constructs the narrow Windows x64 runtime ZIP from exactly five files:

1. `tunnel-client-runtime.exe`
2. `LICENSE`
3. `NOTICE`
4. `tunnel-client-runtime-v0.0.12-windows-amd64-licenses.txt`
5. `tunnel-client-runtime-v0.0.12-windows-amd64.spdx.json`

## Acquisition authority

The only network acquisition URL in this tranche is the official release URL for the pinned asset:

`https://github.com/openai/tunnel-client/releases/download/v0.0.12/tunnel-client-runtime-v0.0.12-windows-amd64.zip`

Acquisition rules:

- every archive read, including operator-supplied provisioning input, requires the exact pinned asset basename;
- destination basename must equal the pinned asset name;
- destination parent must already be a stable non-reparse directory;
- publication is create-only and never overwrites an existing archive;
- initial request and final redirected URL must remain HTTPS;
- a supplied `Content-Length`, when present, must equal `6,950,001`;
- streaming is bounded to the exact pinned size;
- the completed bytes must equal SHA-256 `0721098f9edda72cc36f938adcb12cd6a0c49c6c0be7ad6ab6e412f966585f2e` before create-only publication;
- readback from the published file is revalidated.

The current ChatGPT execution environment could not transport the binary release asset for direct inspection, so this checkpoint still does not claim that **this session** independently read those 6,950,001 ZIP bytes. The staged Windows acquisition path is the mechanism that performs that byte-level proof before installation.

## Exact extraction authority

HMS does not use `ZipFile.extractall()`.

The verified archive bytes are held in one in-memory authority for member inspection and extraction. Extraction requires:

- exactly the five expected member names, no duplicates;
- simple basenames only; no path traversal or nested paths;
- no directories;
- no encrypted members;
- no symlink/special-file Unix type metadata;
- bounded individual and total uncompressed sizes;
- exact declared-size reads;
- create-only file publication into a private staging directory;
- per-file SHA-256 readback before staging publication;
- no unexpected staging entry;
- atomic directory rename into the fixed version root.

A staging ownership marker allows HMS to clean only a staging directory it created. Existing install targets are never silently replaced.

## Immutable installed package authority

The tunnel runtime is **not** installed under the writable Bridge runtime directory.

Fixed package authority:

- package root: `C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client`
- version root: `C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12`
- executable: `C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12\tunnel-client-runtime.exe`
- HMS manifest: `C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\hms-tunnel-runtime.manifest.json`

Privileged provisioning requires the existing HMSBridge provisioning identity proof: elevated Administrator, exact HMSBridge virtual account/service SID, service `Manual`, service `Stopped`.

The canonical HMS package manifest records:

- schema version;
- upstream version;
- pinned archive name/size/SHA-256;
- exact five installed file names;
- exact per-file sizes and SHA-256 values derived only from the verified archive bytes.

The manifest is create-only. An existing manifest or installed package that differs from the current verified archive fails closed instead of being overwritten.

Package ACL authority is protected and exact:

- SYSTEM: FullControl;
- Administrators: FullControl;
- exact `NT SERVICE\HMSBridge` service SID: ReadAndExecute only.

The service therefore cannot rewrite its supervised tunnel binary. Runtime package proof brackets file hashing with observer-mode ACL proof so a writable service package is rejected before any executable is trusted.

## Runtime health handshake

The runtime uses a writable transient path only for health discovery:

`C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-<random>\health-url.txt`

Every process start uses a fresh random attempt directory. No stale fixed health URL file is reused.

The child is launched with non-secret health flags:

`<absolute tunnel-client-runtime.exe> run --health.listen-addr 127.0.0.1:0 --health.url-file <fresh path> --mcp.startup-wait-timeout 30s`

The restricted runtime API key remains environment-only as previously locked.

HMS accepts the URL-file handshake only if it is canonical ASCII of the exact form:

`http://127.0.0.1:<1..65535>`

No hostname aliases, credentials, HTTPS substitution, path, query, fragment, or whitespace are accepted.

## Readiness authority

Process creation is not readiness.

Startup remains pending while:

- the health URL file does not yet exist;
- the health listener is not yet reachable; or
- `/readyz` returns HTTP `503`.

Readiness commits only after all of the following hold in the same startup generation:

1. the supervised process is still alive;
2. the health URL handoff pins exact loopback;
3. `/readyz` returns HTTP `200`;
4. response body is exact upstream `ready`, or the exact upstream `ready (mcp initialize requires auth: ...)` class required for HMS OAuth-protected MCP;
5. HMSBridge runtime identity is re-proven;
6. immutable package content and ACL authority are re-proven;
7. the stop signal is still clear.

Upstream v0.0.12 also emits HTTP `200` for `ready (mcp startup probe timed out: ...)`. HMS deliberately rejects that 200 form: a timed-out MCP initialization is not sufficient HMS readiness.

Any non-`503`/non-approved-`200` response during startup fails closed. After readiness, any process exit, unreachable health endpoint, or readiness loss fails closed immediately.

## Secret boundary

The supervisor:

- never places `CONTROL_PLANE_API_KEY` in argv;
- never writes the API key to the health handshake or HMS package manifest;
- launches without a shell;
- sends stdin/stdout/stderr to null in the production process factory so raw child diagnostics cannot accidentally persist secrets through HMS logs;
- clears the mutable child-environment API-key value immediately after process creation returns or fails;
- stores no raw runtime key in supervisor fields or repr.

## Crash / restart authority

There is deliberately **no blind child restart loop** inside `SecureMcpTunnelRuntime`.

If the tunnel child exits unexpectedly or loses readiness, the failure bubbles out of the HMSBridge process. The existing HMSBridge SCM authority already configures service failure actions as bounded restarts after 5 seconds, 15 seconds, and 60 seconds. A new HMSBridge service generation therefore re-runs service identity, secret ACL, immutable package, fresh health-attempt, and `/readyz` proofs instead of reusing possibly ambiguous in-process state.

Shutdown is bounded:

1. `terminate()`;
2. bounded wait;
3. `kill()` only if the terminate wait times out;
4. second bounded wait;
5. cleanup only the fresh owned health attempt.

## Production service integration ordering

The supervisor is now staged into the HMSBridge production service lifecycle. Runtime configuration schema v2 carries one durable, non-secret `tunnel_id`; the service does not accept a tunnel-id argv, environment, or mutable side-config override. The protected create-only `bridge-runtime.json` remains the durable authority.

Startup is locked to:

`HMSBridge identity + protected config/secrets -> Agent TLS -> local MCP 127.0.0.1:8765 -> SecureMcpTunnelRuntime -> fresh /readyz proof -> SCM ready`

The service rechecks the local MCP listener and calls `SecureMcpTunnelRuntime.assert_healthy()` on a bounded steady-state cadence. Tunnel child exit, unreachable health, or degraded `/readyz` therefore fails HMSBridge closed and delegates bounded restart to the existing SCM failure policy. Merely retaining a previously true `ready` property is not sufficient.

Shutdown is ordered `tunnel -> local MCP -> Agent TLS` so cloud ingress is removed before the local endpoint is torn down.

Host deployment is also staged to provision and re-prove the pinned tunnel runtime package, package ACL, LocalMachine-DPAPI tunnel API key, and exact service secret ACLs before the schema-v2 Bridge runtime config is published. The create-only deployment transaction still leaves HMSBridge `Stopped/Manual` and reports `tunnel_runtime_started=false` and `tunnel_ready=false`; provisioning is not execution proof.

## Evidence boundary at this checkpoint

Focused local regression for package/supervisor plus production-service/deployment wiring passes `44/44` tests in the staged dependency-isolated harness. The supervisor suite now also exercises the public one-shot health assertion used by HMSBridge. Defects found and remediated before publication include:

- ZIP Unix permission-only mode must not be misclassified as a special file;
- unexpected child exit must retain its specific exit-code failure instead of being hidden by a derived `ready=false` property;
- process-spawn failure must scrub the mutable API-key environment and remove its fresh health attempt;
- shutdown must escalate terminate to kill only after the bounded wait expires.

This is not GitHub CI and not Windows production proof.

Project-level status remains `STAGED_NOT_EXECUTED` until a real Windows qualification observes package acquisition, LocalMachine DPAPI key use, protected schema-v2 config consumption, child creation, composite TLS/MCP/tunnel SCM readiness, health URL publication, `/readyz=200`, authenticated tunnel attachment, and an actual OpenAI/MCP principal flow.
