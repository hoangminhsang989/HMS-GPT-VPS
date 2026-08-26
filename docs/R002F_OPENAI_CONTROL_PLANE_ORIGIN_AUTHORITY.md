# R002F OpenAI control-plane origin authority

Status: `STAGED_NOT_EXECUTED`.

This tranche makes **OpenAI tunnel control-plane command origin** eligible for a future real Windows qualification. It does not claim that a particular ChatGPT UI, conversation, user gesture, or product surface originated the command.

## Exact upstream authority

- repository: `openai/tunnel-client`
- tag: `v0.0.12`
- annotated tag object: `5cdcc62932cbf21bd94c4321ab337b0ede51103a`
- commit: `881c9a8fed7cccbe6607cd419863bbca506b8215`
- tree: `fee5968ecb711a6cd1dd4df9f322f62fae613b28`
- release workflow blob: `56fb83cad8682db8190ab837d1c3fdce523996f4`
- Windows amd64 runtime release asset id: `521784635`
- asset: `tunnel-client-runtime-v0.0.12-windows-amd64.zip`
- size: `6950001`
- SHA-256: `0721098f9edda72cc36f938adcb12cd6a0c49c6c0be7ad6ab6e412f966585f2e`
- runtime default control plane: `https://api.openai.com`

The exact v0.0.12 release workflow builds the runtime from `./cmd/client-runtime`, embeds `GITHUB_SHA`, verifies the runtime/source boundary, builds a matching runtime source export, generates per-platform metadata plus scan manifests and `SHA256SUMS.txt`, attests `dist/public/*`, and publishes those artifacts together in the tag release. The GitHub release asset digest above exactly matches the existing HMS archive pin.

## Origin theorem

A real qualification may set `openai_control_plane_origin_proven=true` only if all of these hold in one challenged flow:

1. B2 proves the exact external `read_file(instance_id, request_id, path)` crossed the protected `/mcp` gate and durable principal/session/Agent chain.
2. The durable request ingress generation equals the independently qualified native tunnel generation before and after the request.
3. The live tunnel child is the installed runtime package child of the exact HMSBridge PID, with package manifest/file integrity already proven from the pinned official release ZIP.
4. A native command-line probe proves the child launch argv is exactly the closed HMS runtime profile: `run`, loopback health listener, the exact generation health-url file, and bounded MCP startup wait. No config/profile/control-plane URL or other argument is permitted.
5. HMS child environment construction remains closed: arbitrary host env, proxy variables, `CONTROL_PLANE_BASE_URL`, and tunnel-client config/profile selectors are not inherited. Only fixed OS bootstrap variables plus HMS tunnel/API/MCP/ingress variables are present.
6. The audited v0.0.12 runtime defaults the control-plane base URL to `https://api.openai.com`; without config/profile/env/argv overrides there is no reviewed redirect path.
7. In the audited production Fx graph, the dispatcher command queue is created once and the production producer is the authenticated control-plane poller. Startup MCP probing is a distinct path and does not synthesize an arbitrary challenged HMS `read_file`.

Under the existing trusted-host/HMSBridge-service boundary, these conditions close the production path from an authenticated OpenAI tunnel-service command to the protected local MCP invocation.

## Explicit non-proofs

- Aggregate `commands_polled` or latency metrics are not request provenance.
- A forwarded `X-Request-Id` header is not cryptographic provenance.
- The command envelope `request_id` is not forwarded to MCP by v0.0.12 as a protected header.
- The static ingress header can be overwritten by a command header; without the secret this causes rejection/DoS, not a bypass.
- This tranche does not prove ChatGPT UI origin.
- This tranche does not itself set `full_bridge_command_flow_proven=true`.
- No Windows/Hyper-V/OpenAI live qualification has been executed in this repository session.
