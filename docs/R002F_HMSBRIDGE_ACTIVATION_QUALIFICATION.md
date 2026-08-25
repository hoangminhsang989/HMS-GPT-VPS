# R002F — HMSBridge activation qualification gate

Status: `STAGED_NOT_EXECUTED`

This tranche stages the first controlled service activation after the create-only host deployment transaction. It does not make the service persistent/Automatic and it does not claim authenticated Agent transport, command flow, bootstrap retirement, or pairing readiness.

## Qualification contract

1. Load the protected production `bridge-runtime.json` and derive the frozen `HMSBridge` service SID.
2. Load and verify the complete deployed `hms-bridge` onedir manifest/tree and AMD64 PE entrypoint.
3. Require the exact elevated provisioning identity and `HMSBridge` to be `Manual` + fully `Stopped` before activation.
4. Start the exact pinned service command and wait for SCM `Running`.
5. Require the same service process PID to own exactly one Agent TLS listener at `172.29.240.1:9443` and exactly one MCP listener at `127.0.0.1:<configured MCP port>`.
6. Re-observe the service after listener readiness and require a stable Running PID and zero Win32/service-specific exit codes.
7. From the managed VM, run the existing external production TLS qualification and require exact VMId, Bridge origin and server-certificate SHA-256.
8. In all success/failure paths after a successful start, stop `HMSBridge`, wait for PID 0 and prove both listeners are absent.
9. Re-prove exact service SID, `Manual`, and `Stopped` after qualification.

SCM `Running` is not treated as a generic liveness signal: the committed Windows service host reports Running only after strict `NT SERVICE\HMSBridge` runtime identity proof and successful Agent TLS + MCP runtime startup. This gate additionally pins the deployed package/binary and listener ownership to the observed service PID.

## Failure semantics

- Pre-existing TLS or MCP listeners block activation.
- Startup failures trigger an emergency exact-service stop attempt.
- If startup proof fails and emergency stop also fails, the stop failure is surfaced explicitly rather than hidden.
- Managed-guest TLS qualification failures still force the service back to Stopped.
- The gate never changes the start mode and never calls `sc config ... start= auto` or equivalent.

## Result authority

A successful executed probe may prove:

- service runtime readiness during the bounded probe,
- exact local TLS/MCP listener ownership during the probe,
- live managed-guest TLS against the pinned certificate,
- clean listener removal after stopping.

It deliberately leaves these false:

- authenticated Agent transport,
- full Bridge command flow,
- bootstrap retired,
- pairing ready,
- Automatic start enabled.

## Validation performed while staging

- Python syntax compile: PASS.
- Focused PowerShell start/stop contract regression authored.
- Synthetic success ordering and always-stop regression authored.
- Synthetic qualification-failure still-stop regression authored.
- Repository pytest / real Windows-Hyper-V execution: NOT RUN in this environment.
