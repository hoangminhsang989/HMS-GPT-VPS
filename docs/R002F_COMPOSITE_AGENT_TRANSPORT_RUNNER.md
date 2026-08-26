# R002F — Composite authenticated Agent transport runner

## Status

`STAGED_NOT_EXECUTED`

This checkpoint stages the explicit Windows runner for tunnel-bracketed authenticated HMSAgent transport qualification.

The thin script is `scripts/qualify_hms_bridge_composite_agent_transport.py`. Its only command-line input is the non-secret create-only `--proof` target. PowerShell Direct bootstrap username/password reuse the existing environment ingress `HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME` and `HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD`; both values are consumed with `pop()` and are never accepted as argv parameters.

`run_composite_agent_transport_qualification(...)` requires Windows Administrator authority, builds the existing secret-hiding transport request, runs `qualify_authenticated_agent_transport_with_secure_tunnel(...)`, validates the exact result schema and fail-closed boundary, and publishes one bounded JSON proof through `write_json_create_only(...)`.

A publishable result must prove the Secure MCP Tunnel remained one generation across authenticated Agent hello, heartbeat, poll and result, and must prove authenticated Agent transport. It must still report `full_bridge_command_flow_proven=false`, `bootstrap_retired=false`, `pairing_ready=false`, and `automatic_start_enabled=false`.

This runner is not the final ChatGPT/MCP command-flow qualification. The current `git.status` action originates from the internal Bridge qualification queue, not an externally authenticated request entering through the OpenAI tunnel/MCP surface.

Pre-publication synthetic validation: direct syntax compilation PASS; secret-env consumption PASS; exact proof-boundary validation PASS; create-only publication ordering PASS; combined current service/tunnel/composite harness 66/66 PASS. No real Windows/SCM/Hyper-V/DPAPI/tunnel/Agent execution occurred here, so status remains `STAGED_NOT_EXECUTED`.
