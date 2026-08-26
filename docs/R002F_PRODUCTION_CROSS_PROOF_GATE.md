# R002F production cross-proof gate

Status: `STAGED_NOT_EXECUTED`

This tranche adds a read-only consolidation gate for four proof artifacts that already exist as independent R002E/R002F qualification paths:

1. strict managed Hyper-V Agent qualification;
2. HMSBridge composite activation;
3. authenticated Agent transport with the secure MCP tunnel; and
4. OpenAI control-plane MCP principal-read qualification.

The gate does **not** start or stop a VM, HMSBridge, HMSAgent, or the OpenAI tunnel. It does not mutate provisioning state and does not retire bootstrap credentials. Its only publication is one create-only JSON proof after all component artifacts have been read through the existing pinned-file authority and validated again.

## Why this gate exists

A PASS from four independent runners is not enough if the artifacts can belong to different machines, guests, devices, or logical instances.

The cross-proof gate therefore requires the identity chain to close:

- strict managed Hyper-V `vm_id` == composite activation `vm_id`;
- strict managed Hyper-V `device_id` == authenticated transport `agent_device_id`;
- strict managed Hyper-V `health_boot_id` == authenticated transport `agent_boot_id`;
- strict managed Hyper-V `instance_id` == OpenAI control-plane `instance_id`;
- the exact `tunnel_executable_sha256` is identical across composite activation, authenticated Agent transport, and OpenAI control-plane proofs.

Every input artifact is SHA-256 bound into the output proof.

The existing production validators remain authoritative for each component result. The gate additionally rejects duplicate-key JSON, non-UTF-8 input, link/reparse redirected proof paths, oversized artifacts, component outer-schema drift, and reused input/output paths.

## Proof that may be consolidated

When all four already-executed artifacts validate and cross-bind, the gate may state:

- `hyperv_guest_proven=true`
- `live_managed_guest_tls_proven=true`
- `authenticated_agent_transport_proven=true`
- `openai_control_plane_origin_proven=true`
- `durable_external_principal_read_proven=true`
- `cross_proof_identity_binding_proven=true`

These statements describe the four live proof layers and their identity consistency. They do not claim that this GitHub tranche itself executed those layers.

## Proof that remains false

Even a successful cross-proof gate must keep:

- `chatgpt_ui_origin_proven=false`
- `token_specific_client_auth_attestation_proven=false`
- `token_endpoint_private_key_jwt_exchange_proven=false`
- `chatgpt_app_oauth_client_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`
- `automatic_start_enabled=false`

The OpenAI control-plane runner proves an authenticated OpenAI tunnel/control-plane principal read, but it intentionally does not prove a specific ChatGPT UI/user gesture. The current tunnel topology also does not expose the original ChatGPT mTLS peer certificate to the loopback HMSBridge MCP listener.

OAuth-provider authority and ChatGPT-specific token/UI provenance therefore remain independent blockers.

## CLI

After the four real proof files exist:

```powershell
python scripts/verify_r002f_production_proof_bundle.py `
  --managed-hyperv-proof <strict-managed-hyperv-proof.json> `
  --composite-activation-proof <composite-activation-proof.json> `
  --agent-transport-proof <authenticated-agent-transport-proof.json> `
  --openai-control-plane-proof <openai-control-plane-proof.json> `
  --proof <new-cross-proof.json>
```

The output path must not already exist.

## Execution boundary

At commit time this tranche is code/test/document authority only. Repository-wide pytest, GitHub CI, Windows Administrator execution, Hyper-V guest execution, tunnel execution, ChatGPT OAuth, and a full ChatGPT-to-Agent command remain separately unproven until real artifacts are produced.
