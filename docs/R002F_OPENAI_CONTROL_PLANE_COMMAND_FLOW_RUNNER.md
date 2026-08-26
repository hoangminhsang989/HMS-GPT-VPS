# R002F OpenAI control-plane command-flow runner

Status: `STAGED_NOT_EXECUTED`.

This runner is the Windows Administrator entrypoint for the narrow OpenAI tunnel control-plane origin qualification. It invokes only `qualify_openai_control_plane_mcp_read`; it does not fall back to the older B2 qualification.

The runner:

- consumes bootstrap username/password from the existing environment variables and removes them from the mutable environment before qualification;
- requires distinct create-only challenge and proof paths;
- receives a canonical source commit, workspace-relative path and expected content SHA-256;
- never self-invokes MCP and never directly enqueues an Agent command;
- requires protected MCP ingress provenance, exact native tunnel generation, exact live tunnel launch profile and the pinned v0.0.12 OpenAI upstream/release authority;
- requires final HMSBridge `Stopped/Manual` and no listener residue;
- publishes a bounded create-only proof only after strict exact-schema validation.

A successful future native run may contain `openai_control_plane_origin_proven=true` with the narrow meaning **authenticated OpenAI tunnel-service control-plane command origin**. The runner requires `chatgpt_ui_origin_proven=false` and `full_bridge_command_flow_proven=false`; it cannot be used to claim either stronger property.

No Windows/Hyper-V/OpenAI live run has been executed in this repository session.
