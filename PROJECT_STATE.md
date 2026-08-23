# PROJECT STATE — HMS-GPT-VPS

## Current revision

R002C — Windows unattended install foundation (Tranche 3)

## Status

IN_PROGRESS

## Authority

- Repository: `hoangminhsang989/HMS-GPT-VPS`
- Default branch: `main`
- Repository visibility: private
- GitHub is the source-of-truth for source and working documentation.

## Product authority

The canonical product is a Windows desktop tool that creates and manages an isolated Windows Hyper-V VM on the same Windows PC.

Primary workflow:

`Tạo VPS -> detect/enable Hyper-V with approval -> resume after reboot -> verify Windows image -> ensure isolated Internal vSwitch/NAT -> create/recover identity-pinned Windows VM -> create transient answer media -> unattended Windows install -> PowerShell Direct guest bootstrap -> install least-privilege HMS Agent -> create C:\HMS-Workspace -> outbound authenticated control -> one-time pairing link/code -> supported ChatGPT/HMS integration -> file/test/git operations inside the VM.`

Windows is the primary guest OS. Linux/WSL2 and remote VPS backends remain optional future modes.

## Delivered foundation

### R001

- fail-closed policy;
- workspace isolation;
- append-only audit;
- policy-gated executor;
- read-only Git operations;
- health CLI;
- unit tests and CI.

### R002 / R002A / R002B

- Hyper-V prerequisite/configuration model;
- Windows host/Hyper-V probe;
- persistent instance registry;
- elevation and approval gates;
- Hyper-V enable + reboot/resume state;
- Windows ISO/SHA-256 validation;
- VM readiness/heartbeat foundation.

### R002C Tranche 1 — persistent orchestration / control contract

- atomic `ProvisionStateStore`;
- reconcile-oriented `ProvisioningOrchestrator`;
- structured PowerShell runner;
- initial secret-free unattend preview;
- `docs/R002C_ARCHITECTURE.md`;
- `docs/CONTROL_PROTOCOL.md` clarifying that a pasted link alone cannot give ordinary ChatGPT shell access; a compatible connector/MCP/Bridge control surface is required.

### R002C Tranche 2 — Hyper-V reconciliation

- escaped PowerShell literals;
- Internal vSwitch + NAT default (`HMS-GPT-VPS-Internal`, `HMS-GPT-VPS-NAT`);
- no inbound NAT static mappings by default;
- VM reconcile pinned to persisted Hyper-V `VMId`;
- no silent VM adoption;
- no automatic stop/reset during static reconciliation;
- Generation-2 Secure Boot using Microsoft Windows template;
- read-only Hyper-V observation;
- dual read-after-write verification semantics;
- state-machine fix to `observe -> decide -> mutate -> observe -> verify -> advance`;
- `docs/R002C_HYPERV_RECONCILIATION.md`;
- regression tests for network isolation, PowerShell escaping, VM identity and postconditions.

### R002C Tranche 3 — Windows unattended install foundation now adds

- `pycdlib` dependency for pure-Python local ISO authoring;
- atomic `answer_media.py` creating a secondary ISO with root `Autounattend.xml` and exact readback verification;
- full guarded `generate_install_unattend()` path;
- GPT guest layout: EFI 300 MB + MSR 16 MB + remaining Windows NTFS partition;
- explicit acknowledgement gate before generating `WillWipeDisk=true`;
- Windows image selection by `/IMAGE/INDEX` without product-key injection or activation bypass;
- OOBE automation using explicit OOBE/account settings rather than `SkipMachineOOBE`;
- temporary local Administrator bootstrap account only for post-install PowerShell Direct;
- runtime cryptographic bootstrap password generation;
- password redacted from Python dataclass `repr()`;
- current-user Windows DPAPI store for transient resume credential;
- DPAPI native x64 pointer-safe `LocalFree` handling;
- Windows 11 VM baseline extended with local-key-protected vTPM;
- Hyper-V observer extended with Secure Boot/vTPM postconditions;
- dual-DVD install-bundle reconcile: Windows product ISO + transient answer ISO;
- refusal to silently replace unrelated/operator-owned DVD media;
- read-only install-bundle observer;
- destructive install start gate requiring exactly one managed VHDX, complete media bundle, Secure Boot and vTPM;
- answer-media SHA-256 revalidation immediately before attach/start;
- `WindowsInstallRuntime` executing network/VM/media/start actions with postcondition verification;
- transient install artifact pipeline returning only non-secret metadata;
- regression tests for credential secrecy, DPAPI platform behavior, answer-media generation, GPT XML layout, vTPM baseline and destructive target gate;
- `docs/R002C_WINDOWS_INSTALL.md`.

## Architecture decisions locked

1. Hyper-V Windows VM is the production default isolation boundary.
2. Host and guest control planes remain separate; ChatGPT/HMS targets the guest agent, not Hyper-V host Administrator APIs.
3. Provisioning is persistent/reconcile-oriented and state advances only after observed postconditions.
4. Internal vSwitch + NAT is the managed default; guest is not bridged directly onto the physical LAN.
5. PowerShell Direct is the preferred host-to-guest bootstrap transport because it does not require guest network management ports.
6. Windows product ISO remains unchanged; a separate transient answer ISO carries `Autounattend.xml`.
7. Windows 11 guest baseline requires Generation 2 + Secure Boot + vTPM.
8. Full unattended media is a transient secret artifact because it contains the temporary bootstrap password; it must never be committed/logged and must be removed after bootstrap.
9. Bootstrap credential recovery on Windows host uses DPAPI current-user scope, not plaintext JSON/state.
10. No Windows product key, pairing token or reusable HMS Agent credential is embedded in unattended media.
11. A pairing URL/code is only bootstrap authorization for a compatible HMS integration; ordinary ChatGPT cannot execute arbitrary URL commands by itself.

## Security baseline

1. Deny by default.
2. No default ChatGPT path to the physical Windows host.
3. No implicit host-drive sharing.
4. Guest workspace access restricted to configured roots.
5. Normal HMS Agent work must run non-admin.
6. Destructive/privileged operations require explicit approval.
7. Host elevation is never implied by normal guest-control requests.
8. Reusable plaintext credentials must not appear in Git, pairing URLs or normal audit logs.
9. Pairing/session credentials are scoped, expiring, revocable and independently rotatable.
10. VM identity is pinned by VMId; identity conflicts fail closed.
11. Default NAT exposes no inbound guest management mapping.
12. `WillWipeDisk` is permitted only for the exact dedicated managed guest VHDX after destructive-target verification.
13. Unknown DVD media is not silently replaced.
14. Transient answer-media integrity is verified by SHA-256 immediately before Windows Setup.
15. Temporary bootstrap Administrator must be retired after Agent bootstrap and its answer-media/DPAPI artifacts cleared.

## Verification status

### Deterministic/code-level

The repository now contains tests for the core Python models, generated XML/ISO behavior, PowerShell command shape, secret redaction, fail-closed gates and provisioning postcondition semantics.

### Not yet runtime PASS

A real Windows Hyper-V integration run is still mandatory. Current GitHub CI cannot prove actual Hyper-V/vTPM/NAT/firmware behavior, Windows Setup answer-file consumption, DPAPI native round-trip on the target host, or PowerShell Direct bootstrap.

Do **not** label R002C runtime PASS until those Windows-host tests are executed and evidence is captured.

## Next objectives

### R002C Tranche 3B — real Windows/Hyper-V install harness

- add Windows-only integration marker/harness;
- preflight report for Hyper-V/network/media conflicts;
- reconcile Internal vSwitch/NAT twice for idempotency proof;
- create VM, persist VMId, reconcile by VMId;
- prove Secure Boot + vTPM readback;
- attach Windows + answer ISO and verify boot order;
- run DPAPI native round-trip;
- start unattended Windows installation on an explicitly designated disposable test VM;
- capture non-secret evidence JSON;
- no automated destructive cleanup without explicit operator approval.

### R002C Tranche 4 — PowerShell Direct guest bootstrap

- implement secret-safe `Invoke-Command -VMName` runner;
- load bootstrap credential from DPAPI without command-line exposure;
- wait for PowerShell Direct readiness/user profile;
- configure deterministic guest IP `172.29.240.10/24`, gateway `172.29.240.1`, managed DNS;
- create `C:\HMS-Workspace` and NTFS ACLs;
- install HMS Agent as a Windows Service with least privilege;
- health/capability proof;
- disable/remove temporary bootstrap Administrator and AutoLogon residue;
- detach/delete answer ISO and clear DPAPI secret.

### R002C Tranche 5 — pairing/control proof

- one-time pair-token lifecycle;
- outbound authenticated Agent <-> Bridge session;
- compatible ChatGPT MCP/connector/action surface;
- `workspace.read`, `workspace.write`, `process.test`, `git.status`, `audit.read`;
- session rotation/revocation/idempotency;
- canonical end-to-end file proof.

## Canonical end-to-end target

ChatGPT, through the supported HMS control integration, creates `C:\HMS-Workspace\chatgpt-control-test.txt` inside the managed Windows VM, reads it back through the same authenticated path, and receives matching SHA-256, byte size, timestamp and audit event ID — without host filesystem sharing or host Administrator control.
