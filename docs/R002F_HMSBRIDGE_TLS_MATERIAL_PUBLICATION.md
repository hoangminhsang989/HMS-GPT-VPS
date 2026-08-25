# R002F — HMSBridge TLS material create-only publication authority

Status: `STAGED_NOT_EXECUTED`

This tranche adds the privileged publication boundary for the production Agent Bridge TLS certificate/private-key pair. It does not start HMSBridge and it does not claim any live TLS, authenticated Agent transport, command-flow, or pairing proof.

## Fixed production authority

- TLS material root: `C:\ProgramData\HMS-GPT-VPS\Bridge\tls-material`
- Certificate: `C:\ProgramData\HMS-GPT-VPS\Bridge\tls-material\certificate\agent-bridge.pem`
- Private-key root: `C:\ProgramData\HMS-GPT-VPS\Bridge\tls-material\private`
- Private key: `C:\ProgramData\HMS-GPT-VPS\Bridge\tls-material\private\agent-bridge-private-key.pem`

The runtime config and TLS storage authority must point to these exact paths.

## Security ordering

1. Validate exact configured paths and pinned certificate DER SHA-256/private-key file SHA-256.
2. Prove elevated provisioning identity and `HMSBridge` remains `Manual` + `Stopped`.
3. Create a same-parent staging root using only non-secret PowerShell arguments.
4. PowerShell protects staging directories and pre-creates both files with SYSTEM/Administrators-only DACLs before any private-key bytes are written.
5. Python writes certificate/private-key bytes directly to the pre-created protected files. Private-key bytes never enter PowerShell, argv, logs, GitHub, or runtime JSON.
6. Load the staged pair through the existing `load_agent_bridge_tls_material()` authority. This proves the certificate/key pair and pinned hashes before publication.
7. Re-prove provisioning identity.
8. Atomically publish the whole staged root with `Directory.Move`; publication is create-only and refuses an existing final root.
9. Grant exact HMSBridge read-only private-key access through the existing TLS storage authority. A second pass must be observer-equivalent (`changed=False`).
10. Reload the final TLS material through the existing loader and re-prove the stopped/manual HMSBridge identity.

## Fail-closed behavior

If validation fails before the final move, the production TLS root is not published. If a post-move ACL or final-load proof fails, the function raises and never starts HMSBridge; the final root is intentionally not deleted automatically because destructive rollback of an already-published security authority requires separate ownership/rollback policy.

Returned evidence contains hashes, paths, SID/state and readiness booleans only. It never contains the private key or any OAuth secret.

## Validation performed in this tranche

- Python syntax compile: PASS.
- Synthetic import and PowerShell script authority checks: PASS.
- Synthetic full publication ordering/identity/ACL re-proof flow: PASS.
- Repository pytest / Windows native execution: NOT RUN in this environment.

All real qualification flags remain false until the Windows host qualification stage executes against the reviewed committed bytes.
