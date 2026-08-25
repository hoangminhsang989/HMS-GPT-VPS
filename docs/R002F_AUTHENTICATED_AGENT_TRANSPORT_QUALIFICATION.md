# R002F — Authenticated HMSAgent transport qualification

Status: `STAGED_NOT_EXECUTED`

This tranche stages a bounded qualification of the real guest `HMSAgent` production transport after the controlled HMSBridge activation gate. It deliberately does not use a synthetic HMAC client and does not promote the Bridge to Automatic start or pairing readiness.

## Production path under qualification

The guest service runs the existing production chain:

`HMSAgent SCM → AgentGuestRuntime → AgentRuntimeRunner → AgentRuntimeSession → AgentHttpsClient`

The Bridge side uses the existing production chain:

`Agent TLS :9443 → AgentBridgeHttpBoundary → AgentBridgeService → presence/command stores`

The qualification command is the existing read-only `git.status` action with an empty parameter object.

## Proof sequence

1. Require the protected Bridge config/package and exact `HMSBridge` `Manual + Stopped` preflight.
2. Observe the real guest `HMSAgent` over PowerShell Direct: service Running, `NT AUTHORITY\LocalService`, Automatic, loopback `/healthz` reachable, health identity `NT SERVICE\HMSAgent`, privilege `non-admin`, and health/config alignment.
3. Start reviewed HMSBridge with the existing activation gate. This already proves strict Bridge runtime identity plus PID-owned Agent TLS and MCP listener readiness.
4. Observe `agent_presence` through a read-only SQLite connection and require a fresh authenticated generation whose `boot_id` equals the live guest `/healthz` boot id.
5. Hold that exact generation across more than the committed 30-second production heartbeat interval. The production runner attempts heartbeat before poll once due; a retryable heartbeat failure exits the generation and allocates a higher epoch, while auth/schema failure stops the Agent. Stable PID + boot id + epoch across this boundary, with advancing accepted-request time, therefore proves successful authenticated heartbeat without inventing endpoint telemetry.
6. Prove service-machine Agent credential storage before and after loading the LocalMachine-DPAPI credential. Require its `device_id` to equal the authenticated presence.
7. Sign and enqueue one production `git.status` command with a random qualification request id and bounded deadline.
8. Wait for the existing Agent to poll, verify the signed Bridge command, execute through `AgentPolicyCommandExecutor`, and POST the authenticated result. Require the persisted completed result to have the exact `git.status` response schema.
9. Require the same Agent device/boot/epoch and guest service PID after result acceptance.
10. Always stop HMSBridge and prove it returned to exact `Manual + Stopped` with qualification listeners absent.

## Successful native proof meaning

A successful native run can set authenticated hello, heartbeat, poll, result, and Agent transport to true. It still leaves the full principal/MCP-to-Agent Bridge flow, bootstrap retirement, pairing readiness, and HMSBridge Automatic start false.

The direct qualification enqueue is intentional: this tranche proves the Agent transport boundary, not OAuth/MCP principal dispatch. That end-to-end principal flow remains a separate gate.

## Fail-closed behavior

Any mismatch in protected config, package, service identity/state, guest health identity, presence generation, service-machine credential device id, command result schema, or service cleanup aborts qualification. Once HMSBridge has started, cleanup is mandatory; if both qualification and stop fail, the stop failure is surfaced explicitly.

## Staging validation

- Python module syntax compile: PASS.
- Focused regression test syntax compile: PASS.
- Synthetic dependency-stub import: PASS.
- Synthetic focused suite: 5/5 PASS.
- Real repository pytest: NOT RUN in this environment.
- Real Windows/Hyper-V transport qualification: NOT RUN.
