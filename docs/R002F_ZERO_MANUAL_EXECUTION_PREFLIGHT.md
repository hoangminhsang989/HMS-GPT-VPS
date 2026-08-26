# R002F zero/manual-minimal production execution preflight

Status: `STAGED_NOT_EXECUTED`

This tranche adds a read-only Windows preflight for the existing R002F one-shot
production qualification coordinator. It reduces operator input where the
repository already has a production authority and fails closed where it does not.

## What is derived automatically

The preflight loads the protected production Bridge config from the fixed
authority:

`C:\ProgramData\HMS-GPT-VPS\Bridge\bridge-runtime.json`

and therefore derives and cross-checks:

- Bridge runtime root `C:\ProgramData\HMS-GPT-VPS\Bridge\runtime`;
- provision state `C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\provision-state.json`;
- `instance_id`;
- exact Hyper-V `vm_id` and `vm_name`;
- tunnel id;
- MCP/TLS ports;
- trust-root SHA-256 authority;
- HMSBridge must be Stopped/Manual;
- Hyper-V must already be available, enabled, firmware-virtualization ready,
  and not restart-pending;
- exact live VMId must still resolve to the configured VM name.

If `trust_root_der_sha256 == tls_certificate_der_sha256`, the configured Bridge
server certificate is authority-equivalent to the managed-guest trust root and
may be used automatically. Otherwise an explicit trust-root certificate path is
required. The preflight never scans the filesystem for a certificate by digest.

## Authorities that are deliberately not guessed

The following host-side artifacts are not fixed by the current production
configuration and remain explicit until a later authority binds them:

- approved Agent package root;
- approved Agent package manifest;
- host copy of Agent runtime config;
- instance registry path;
- instance runtime directory;
- Bridge-side device credential path;
- a distinct managed-guest trust-root certificate, when applicable;
- challenge source commit;
- challenge workspace path;
- expected challenge content SHA-256.

If any are absent the proof is still published create-only with
`status=BLOCKED_MISSING_AUTHORITY` and an exact `missing_authority` list.

Provided artifacts are not accepted merely because they exist. The preflight
re-validates package content, Agent runtime instance/origin, registry VMId/name,
late-Agent provision state, device credential instance binding, trust-root
certificate digest, and challenge syntax/hash authority.

## Bootstrap credential handling

Run this preflight **before** setting:

- `HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME`
- `HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD`

This is intentional. Existing shared PowerShell helpers inherit the parent
process environment. A read-only preflight must not leak bootstrap credentials
into PowerShell/Git child processes that do not need them. If either variable is
already populated, the preflight immediately emits
`BLOCKED_HOST_PRECONDITION` with
`BOOTSTRAP_SECRET_ENVIRONMENT_MUST_BE_ABSENT_DURING_PREFLIGHT` and performs no
Windows authority probes.

A successful preflight records only the two environment variable **names** and
states that they must be supplied for the subsequent one-shot execution. It
never stores or prints their values.

## Successful output

When all non-secret authority and host prerequisites are valid, the create-only
proof has:

`status=READY_FOR_ONE_SHOT_EXECUTION`

and contains:

- exact clean checkout HEAD used as `runner_source_commit`;
- secret-free `one_shot_argv`;
- a PowerShell-safe rendered command;
- derived production identity/path evidence;
- `execution_started=false`;
- `hyperv_mutated=false`;
- `bridge_started=false`;
- `tunnel_started=false`.

The preflight never launches the one-shot coordinator.

## CLI

Example with explicit host-side authorities:

```powershell
python scripts/preflight_r002f_one_shot_production_qualification.py `
  --repo-root C:\path\to\HMS-GPT-VPS `
  --proof D:\HMS-Proofs\r002f-preflight.json `
  --package-root D:\HMS-Authority\agent-package `
  --package-manifest D:\HMS-Authority\agent-package-manifest.json `
  --runtime-config D:\HMS-Authority\agent-runtime.json `
  --instance-registry D:\HMS-Authority\instances.json `
  --instance-runtime-dir D:\HMS-Authority\instance-runtime `
  --bridge-device-credential D:\HMS-Authority\bridge-device.dpapi `
  --challenge-source-commit <40-hex-commit> `
  --challenge-workspace-path README.md `
  --challenge-expected-sha256 <64-hex-sha256>
```

Add `--trust-root-certificate` only when the trust-root certificate is a
separate authority. `--run-dir` is optional; otherwise a deterministic new
directory beside the preflight proof is proposed.

The proof itself must be outside the source checkout so publication cannot make
the exact-clean checkout dirty.

## Proof boundary

This tranche is code/test/document authority only. It does not prove a Windows
execution, Hyper-V guest, tunnel, ChatGPT OAuth/UI provenance, bootstrap
retirement, pairing readiness, or a full command flow. Project-level proof
booleans remain false until the existing live qualification chain is actually
executed and its artifacts pass the cross-proof gate.
