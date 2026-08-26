# R002F — Authenticated Agent transport with stable Secure MCP Tunnel

## Status

`STAGED_NOT_EXECUTED`

This checkpoint adds a stricter authenticated-Agent transport qualification that keeps the independent Secure MCP Tunnel generation under proof for the entire authenticated transport interval. It does not claim an external ChatGPT/MCP command has traversed the tunnel.

## Composite transport authority

`qualify_authenticated_agent_transport_with_secure_tunnel(...)` reuses the existing transport primitives and performs one exact `Stopped -> Running -> Stopped` HMSBridge generation:

1. validate the existing PowerShell Direct qualification request;
2. load/validate the protected Bridge runtime config and pinned HMSBridge package;
3. require exact Stopped/Manual HMSBridge identity;
4. independently observe the already-running managed HMSAgent before Bridge activation;
5. start HMSBridge with the existing TLS/MCP listener ownership authority;
6. independently qualify the Secure MCP Tunnel child against the exact HMSBridge PID;
7. observe a fresh authenticated Agent hello;
8. prove the same Agent generation remains healthy across the heartbeat boundary;
9. re-observe the guest Agent process/boot identity;
10. enqueue the existing read-only `git.status` qualification command with the machine-protected Agent credential;
11. observe the authenticated poll/result and stable presence generation;
12. re-observe the guest Agent process/boot identity;
13. independently qualify the Secure MCP Tunnel again and require the same tunnel generation across the full authenticated hello/heartbeat/poll/result interval;
14. always stop HMSBridge after a successful start, including failure paths;
15. require final exact Stopped/Manual identity.

Tunnel generation stability binds service PID, tunnel PID/parent, immutable executable/hash, health attempt and URL-file authority, loopback health listener, readiness URL/status and approved readiness class.

## Proof boundary

A successful executed probe may set these true:

- `secure_mcp_tunnel_ready_during_transport`
- `tunnel_stable_across_authenticated_transport`
- `authenticated_hello_proven`
- `authenticated_heartbeat_proven`
- `authenticated_poll_proven`
- `authenticated_result_proven`
- `authenticated_agent_transport_proven`

It deliberately keeps these false:

- `full_bridge_command_flow_proven`
- `bootstrap_retired`
- `pairing_ready`
- `automatic_start_enabled`

This distinction is intentional. The qualification command is enqueued internally through the reviewed Bridge command store; it is not an external request arriving through the OpenAI tunnel and MCP endpoint. Therefore tunnel liveness plus authenticated Agent transport is not yet proof of the complete ChatGPT -> tunnel -> MCP -> Bridge -> Agent path.

## Validation boundary

Pre-publication synthetic validation:

- direct syntax compilation: PASS;
- successful tunnel-bracketed authenticated transport ordering: PASS;
- tunnel-generation drift fail-closed + mandatory service stop: PASS;
- transport-result failure mandatory service stop: PASS;
- Agent process/boot generation drift rejection: PASS;
- combined current synthetic service/tunnel/composite harness: 62/62 PASS.

Not executed here:

- repository-wide pytest from a real checkout;
- GitHub Actions;
- real Windows SCM;
- real Hyper-V PowerShell Direct;
- real LocalMachine-DPAPI Agent/tunnel credentials;
- real Secure MCP Tunnel child/listener/`/readyz`;
- real authenticated Agent hello/heartbeat/poll/result;
- any external OpenAI tunnel/MCP command;
- bootstrap retirement or pairing readiness.

Status remains `STAGED_NOT_EXECUTED`.
