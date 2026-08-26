# R002F — Protected MCP request generation binding

Status: `STAGED_NOT_EXECUTED`

This tranche joins the durable per-request MCP ingress provenance staged in B1 with the independently qualified native tunnel ingress generation staged in A2. The join key is the non-secret 32-lowercase-hex `mcp_ingress_generation`.

## Read-only observer

`external_mcp_command_flow_sqlite.load_dispatch_provenance_and_receipt()` opens the exact `control-idempotency.sqlite3` authority read-only (`mode=ro`, `query_only`, explicit read transaction), resolves exactly one challenged principal dispatch, requires exactly one `principal_dispatch_ingress_provenance` row for the same `(session_id, request_id)`, parses it with `McpIngressDispatchProvenance.from_row()`, and requires exact equality with the dispatch intent before accepting the completed idempotency receipt. Missing, duplicate, malformed, or digest-drifted provenance fails closed.

`observe_external_mcp_read_durable_authority()` then returns the immutable provenance generation and sets `mcp_adapter_invocation_proven=true`. It remains unable to claim a live tunnel process by itself and therefore leaves `secure_tunnel_generation_proven=false`.

## Composite native binding

`qualify_external_mcp_read_with_stable_tunnel()` uses `qualify_running_secure_mcp_tunnel_with_ingress_generation()` before challenge publication and again after the completed read. It requires:

1. the ordinary native tunnel generation to remain stable across the request;
2. the durable observer to prove one protected MCP provenance row for the exact challenge request;
3. the observer `mcp_ingress_generation` to equal the native pre-request generation;
4. the same generation to remain present in native post-request evidence; and
5. the existing HMSAgent process/boot/connection generation to remain stable.

The runner never invokes MCP and never enqueues the Agent command itself. On every post-start failure path it still stops HMSBridge and requires the service to return to exact `Stopped/Manual`.

## Eligible proof after a real native run

A successful real run of this reviewed byte set may establish:

- exact principal-bound read result;
- durable authenticated principal control path;
- `mcp_adapter_invocation_proven=true`;
- exact request-specific `mcp_ingress_generation`;
- `secure_tunnel_generation_proven=true`; and
- one stable HMSBridge/tunnel/HMSAgent generation across the external read.

It still does not establish that the initiating party was ChatGPT/OpenAI control plane. Therefore these remain false:

- `openai_control_plane_origin_proven=false`;
- `full_bridge_command_flow_proven=false`;
- `bootstrap_retired=false`;
- `pairing_ready=false`;
- `automatic_start_enabled=false`.

## Staging validation

Focused dependency-isolated validation covers the composite qualification, proof runner, native generation wrapper, read-only provenance join, and observer provenance surface. These tests are static/synthetic only. Repository pytest, GitHub CI, real Windows SCM, Hyper-V, LocalMachine-DPAPI, live OpenAI tunnel, and ChatGPT connector execution are not claimed by this document.
