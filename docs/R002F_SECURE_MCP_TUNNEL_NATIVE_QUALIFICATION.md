# R002F — Secure MCP Tunnel native qualification authority

## Status

`STAGED_NOT_EXECUTED`

This checkpoint stages an independent native Windows qualification authority for the already-supervised Secure MCP Tunnel. It does not start `HMSBridge`, does not execute on a Windows host, and does not claim live tunnel readiness.

## Qualification boundary

`qualify_running_secure_mcp_tunnel(...)` is intended to run only while the reviewed `HMSBridge` service is already in the exact `Running` generation being qualified. It independently proves all of the following before returning ready evidence:

- exact `NT SERVICE\\HMSBridge` service SID, account, Manual start mode, Running state, and the caller-pinned HMSBridge PID;
- one canonical active tunnel health attempt under `C:\\ProgramData\\HMS-GPT-VPS\\Bridge\\runtime\\tunnel-health`;
- exact non-reparse `health-url.txt` handoff and canonical `http://127.0.0.1:<port>` authority;
- exactly one loopback health listener on that port;
- the health-listener owner is a distinct tunnel child process whose `ParentProcessId` is the pinned HMSBridge PID;
- the child executable path is the immutable installed `tunnel-client-runtime.exe` authority and its SHA-256 equals the proved installed package;
- `/readyz` returns HTTP 200 with only an HMS-approved readiness class: exact `ready` or upstream MCP-auth-required readiness;
- HMSBridge PID, tunnel PID, executable/hash, health listener owner, and health URL remain stable after the live readiness probe.

The probe does not accept localhost aliases, non-loopback listeners, a tunnel process that is not an HMSBridge child, a self-reported PID, startup-timeout text, generic HTTP 200 bodies, or alternate package paths.

## Bracketed trust proof

The Python qualification wrapper brackets the native process/socket probe with independent authority checks:

1. prove exact HMSBridge machine secret storage and ACLs;
2. load the restricted tunnel API key;
3. prove immutable tunnel package files and ACLs;
4. run the native Windows process/listener/readiness probe;
5. re-prove the immutable package;
6. re-prove service secret storage/ACLs;
7. reload the API key and require exact constant-time identity across the probe.

The API key is never placed in the PowerShell command, argv, evidence, or returned result.

## Integration ordering

This checkpoint deliberately keeps the new authority separate from `bridge_activation_qualification.py`. The next bounded tranche must wire it into the existing activation generation after HMSBridge TLS/MCP startup and before final service stop, then re-check tunnel stability after the managed-guest TLS probe. This separation keeps the native tunnel process-tree/socket proof independently reviewable.

## Validation boundary

Pre-publication synthetic validation:

- direct Python compilation with warnings-as-errors: PASS;
- standalone native qualification suite: 4/4 PASS;
- combined existing service/tunnel synthetic regression harness plus native qualification suite: 50/50 PASS.

Not executed here:

- repository pytest from a real checkout;
- GitHub Actions;
- real Windows SCM;
- real service/tunnel PIDs;
- real immutable package ACL proof on Windows;
- real LocalMachine-DPAPI API-key load;
- real loopback health listener;
- real `/readyz` response;
- real managed Hyper-V guest;
- authenticated Agent transport;
- full ChatGPT → tunnel → MCP → Bridge command flow.

Therefore production proof flags remain false and the project remains `STAGED_NOT_EXECUTED`.
