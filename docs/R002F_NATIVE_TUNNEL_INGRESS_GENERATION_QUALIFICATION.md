# R002F — Native tunnel ingress-generation qualification

Status: `STAGED_NOT_EXECUTED`

This tranche enriches the existing independently validated native Secure MCP Tunnel evidence with one non-secret `mcp_ingress_generation` derived directly from the active health-attempt path.

It deliberately does not weaken or replace `qualify_running_secure_mcp_tunnel()`. The existing native qualifier remains the authority for HMSBridge service identity, exact service PID, tunnel child PID/parent, executable path/hash, loopback health listener, `/readyz`, service/tunnel/listener stability, tunnel package identity, service-secret ACLs, and restricted API-key stability.

## Generation extraction

The wrapper accepts only the evidence returned by the existing native qualifier and requires:

- `ready is True`;
- `health_attempt_path` ending in exact `attempt-<32 lowercase hex>`; and
- `health_url_path` equal to that exact attempt directory plus `health-url.txt`.

The 32-hex suffix is published as `mcp_ingress_generation`.

Because the production Secure MCP Tunnel runtime now creates the active health-attempt directory from the domain-separated ingress-token generation, this gives the later composite runner an independently observable non-secret generation identity without exposing or loading the ingress capability token.

## Deliberate boundary

This tranche still does not persist the generation beside a principal dispatch and does not prove an MCP adapter invocation for one exact request. Those require the next atomic durable-provenance tranche.

Therefore these remain false:

- `mcp_adapter_invocation_proven`
- `openai_control_plane_origin_proven`
- `full_bridge_command_flow_proven`

## Validation

Focused synthetic tests cover canonical extraction, malformed/case/length rejection, health URL-path drift, exact delegation to the native qualifier, and rejection of unexpected base-schema collision.

Repository pytest: NOT RUN in this environment.
Real Windows / Hyper-V / SCM / LocalMachine-DPAPI / OpenAI tunnel / ChatGPT connector execution: NOT RUN.
