# R002F — Secure MCP Tunnel package / credential / launch authority

## Status

`STAGED_NOT_EXECUTED`

This tranche defines the package pin, secret-custody boundary, and deterministic runtime launch contract for exposing the HMS MCP endpoint through OpenAI's official tunnel runtime. It does **not** claim a live Windows launch, an authenticated OpenAI tunnel, a live ChatGPT principal, or end-to-end production readiness.

## Upstream package authority

HMS pins the official OpenAI `tunnel-client` release `v0.0.12` published on 2026-08-20 and uses only the narrow Windows x64 runtime artifact:

- asset: `tunnel-client-runtime-v0.0.12-windows-amd64.zip`
- release-reported size: `6,950,001` bytes
- SHA-256: `0721098f9edda72cc36f938adcb12cd6a0c49c6c0be7ad6ab6e412f966585f2e`
- runtime executable: `tunnel-client-runtime.exe`
- runtime command: `tunnel-client-runtime.exe run`

The archive must fail closed unless its filename, size, and SHA-256 all match this authority before extraction or use. The executable path must not traverse a symlink/reparse point and its basename must be exactly the official runtime executable name (Windows case-insensitive comparison).

The repository verification for this tranche confirms the release metadata and upstream release workflow/command surface. The official ZIP bytes were **not independently downloaded and inspected in this tranche**, so no direct-byte ZIP-content claim is made here.

## MCP target authority

The only HMS MCP target for this tranche is:

`http://127.0.0.1:8765/mcp`

HMS does not implement or fork the tunnel protocol. The supervised OpenAI runtime is the tunnel implementation; HMS only supplies the exact local MCP target, tunnel identity, restricted runtime credential, process supervision, and readiness policy.

## Credential authority

Runtime authentication uses only:

- `CONTROL_PLANE_TUNNEL_ID`
- `CONTROL_PLANE_API_KEY`

The API key must be an OpenAI **Restricted** key scoped for the tunnel runtime (`Tunnels: Read + Use`). HMS does not use the broader `OPENAI_API_KEY` fallback and does not use an admin key for the long-running runtime process.

The runtime API key is stored as a create-once LocalMachine-DPAPI envelope at the fixed Bridge service secret path:

`service-runtime/openai-tunnel-runtime-api-key.service-machine.dpapi`

The existing `service-runtime` whitelist is extended only for that exact filename. If present, the file is included in the same exact secret-file ACL proof as the pairing key and device credentials: SYSTEM and Administrators retain full control; the exact `HMSBridge` service SID receives read access. Unknown root entries remain fail-closed.

Provisioning order is:

1. reconcile/prove the Bridge secret root authority;
2. create the DPAPI-protected tunnel API-key envelope once;
3. reconcile the Bridge secret root again so the new file converges to the exact file ACL;
4. prove the secret root in observer mode before runtime use.

An existing API-key envelope is never silently overwritten or rotated. A different supplied key against an existing authority fails closed.

## Launch contract

The secret-free launch metadata is:

- absolute verified executable path;
- argv: `<absolute tunnel-client-runtime.exe> run`;
- exact tunnel ID matching `tunnel_[0-9a-f]{32}`;
- MCP target `http://127.0.0.1:8765/mcp`;
- readiness path `/readyz`.

No API key, token, password, or pairing/session credential may appear in argv, a profile file, a persisted launch manifest, or log text.

Immediately before process creation, HMS decrypts the LocalMachine-DPAPI runtime key and builds a short-lived child environment containing the minimum inherited Windows process variables plus exactly these tunnel values:

- `CONTROL_PLANE_TUNNEL_ID=<exact tunnel id>`
- `CONTROL_PLANE_API_KEY=<restricted runtime key>`
- `MCP_SERVER_URL=http://127.0.0.1:8765/mcp`

Sensitive or unnecessary parent variables such as `OPENAI_API_KEY`, `OPENAI_ADMIN_KEY`, arbitrary passwords, and `PATH` are not inherited by this contract. Because an absolute executable path is mandatory, command discovery through `PATH` is unnecessary.

## Readiness and state boundary

A successfully created process is **not** tunnel readiness. HMS may treat the tunnel runtime as ready only after the runtime readiness endpoint returns HTTP `200` for `/readyz` under the supervised runtime's health listener. Authentication failure, non-200 readiness, early process exit, package mismatch, secret-custody failure, or launch-contract drift must fail closed.

This tranche does not alter pairing `READY` authority. The existing rule remains: pairing becomes `READY` only after durable `PrincipalSessionBinding`; tunnel process state alone cannot advance that provision state.

## Evidence boundary

At commit time for this tranche:

- source/test/document authority may be committed on `r002f-pairing-readiness-runtime`;
- PR #11 remains Draft/unmerged;
- `main` remains unchanged;
- no GitHub CI result may be claimed unless an actual run/status is observed;
- no live Windows tunnel, OpenAI principal, `/readyz`, or end-to-end MCP proof may be claimed until separately executed and captured.
