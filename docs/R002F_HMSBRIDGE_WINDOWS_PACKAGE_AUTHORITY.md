# R002F — HMSBridge Windows package authority

Status: `STAGED_NOT_EXECUTED`

This tranche adds a dedicated Windows x64 packaging and complete-tree attestation
authority for `hms-bridge.exe`.

## Build authority

The Bridge package workflow:

1. checks out the exact event SHA with persisted Git credentials disabled;
2. verifies the checkout SHA and clean worktree;
3. installs the pinned `bridge` + `package` dependency groups;
4. runs the focused Bridge package authority tests;
5. builds an onedir `hms-bridge.exe` with PyInstaller;
6. collects the HMS package plus MCP and Uvicorn runtime dependencies;
7. smoke-checks the packaged `--version`;
8. attests the complete package tree and native AMD64 PE entrypoint;
9. uploads the attested onedir tree and manifest.

The manifest is deterministic, rejects links/reparse points through the existing
package-tree primitives, rejects duplicate/case-colliding paths, pins every file
by size and SHA-256, and fixes the entrypoint to `hms-bridge.exe`.

This does **not** start HMSBridge under SCM, publish production credentials,
change Hyper-V/firewall state, or claim a live Bridge qualification. Those remain
separate external Windows qualification gates.

Focused synthetic package-authority validation: `6 passed`; syntax compile PASS.
