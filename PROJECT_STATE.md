# PROJECT STATE — HMS-GPT-VPS

## Current revision

R002C — Guest bootstrap and Agent boundary foundation (Tranche 4)

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

`Tạo VPS -> detect/enable Hyper-V with approval -> resume after reboot -> verify Windows image -> ensure isolated Internal vSwitch/NAT -> create/recover identity-pinned Windows VM -> create transient answer media -> unattended Windows install -> PowerShell Direct guest bootstrap -> copy/verify Agent artifact -> install least-privilege HMS Agent service -> retire bootstrap Administrator -> remove transient install secrets -> outbound authenticated Agent control -> one-time pairing -> supported ChatGPT/HMS integration -> workspace/test/git operations inside the VM.`

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
- state-machine `observe -> decide -> mutate -> observe -> verify -> advance`;
- `docs/R002C_HYPERV_RECONCILIATION.md`;
- regression tests for network isolation, PowerShell escaping, VM identity and postconditions.

### R002C Tranche 3 — Windows unattended install foundation

- pure-Python secondary answer-media ISO with root `Autounattend.xml`;
- explicit `WillWipeDisk=true` acknowledgement gate for the dedicated managed VHDX only;
- GPT guest layout: EFI 300 MB + MSR 16 MB + remaining Windows NTFS partition;
- Windows image selection by `/IMAGE/INDEX` without product-key injection;
- temporary local Administrator bootstrap account;
- random runtime bootstrap password with dataclass repr redaction;
- current-user Windows DPAPI resume secret store;
- x64-safe DPAPI native memory release;
- Generation-2 Secure Boot + vTPM baseline;
- Windows ISO + answer ISO dual-DVD reconcile and boot-order verification;
- destructive install start gate requiring one managed VHDX, complete media, Secure Boot and vTPM;
- answer-media SHA-256 revalidation before attach/start;
- `WindowsInstallRuntime` postcondition-oriented execution;
- `docs/R002C_WINDOWS_INSTALL.md`.

### R002C Tranche 4 — guest bootstrap / Agent boundary foundation now adds

- Windows CI matrix (`windows-latest`, Python 3.11/3.12/3.13) in addition to Linux matrix;
- existing DPAPI test now executes a native protect/unprotect round-trip on Windows CI;
- secret-safe Hyper-V PowerShell Direct runner;
- bootstrap username/password/guest script passed through child-process environment instead of command line;
- environment variables removed inside child PowerShell before guest invocation;
- deterministic guest IP `172.29.240.10/24`, gateway `172.29.240.1` and managed DNS bootstrap;
- guest bootstrap fails closed unless the expected single managed NIC is present;
- initial `C:\HMS-Workspace` + runtime directory ACL foundation;
- verified host-to-guest Agent artifact copy through Hyper-V Guest Service Interface / `Copy-VMFile`, without SMB or host-drive sharing;
- temporary Guest Service Interface enablement restored in `finally`;
- immutable `AgentPackageManifest` with filename/version/size/SHA-256 and tamper detection;
- Agent Windows Service installer using `NT AUTHORITY\LocalService`, not LocalSystem;
- per-service SID `NT SERVICE\HMSAgent` with restricted filesystem rights;
- guest-side Agent SHA-256 verification before SCM mutation;
- service failure-recovery configuration;
- read-only Windows service-readiness probe for SCM account, command, hash, service SID and ACL invariants;
- explicit `application_health = NOT_IMPLEMENTED` until real Agent protocol health exists;
- bootstrap retirement primitive that disables (does not delete) the temporary account;
- AutoLogon disabled and `DefaultPassword` residue removed;
- cached unattend cleanup limited to known files whose content references the managed bootstrap username;
- exact managed answer-ISO detach primitive;
- transient install secret cleanup hardened to managed runtime path + persisted SHA-256;
- cleanup remains idempotent when answer ISO was already removed during crash/resume;
- new regression tests for package tamper detection, service-readiness non-claims, bootstrap retirement and secret cleanup;
- `docs/R002C_GUEST_BOOTSTRAP_AGENT.md`.

## Architecture decisions locked

1. Hyper-V Windows VM is the production default isolation boundary.
2. Host and guest control planes remain separate; ChatGPT/HMS targets the guest Agent, not Hyper-V host Administrator APIs.
3. Provisioning is persistent/reconcile-oriented and state advances only after observed postconditions.
4. Internal vSwitch + NAT is the managed default; guest is not bridged directly onto the physical LAN.
5. PowerShell Direct is temporary bootstrap transport only; it is not the permanent ChatGPT control channel.
6. Windows product ISO remains unchanged; a separate transient answer ISO carries `Autounattend.xml`.
7. Windows 11 guest baseline requires Generation 2 + Secure Boot + vTPM.
8. Full unattended media is a transient secret artifact and must never be committed/logged.
9. Bootstrap credential recovery on the host uses current-user DPAPI, not plaintext state.
10. Permanent HMS Agent service runs as `LocalService` plus a per-service SID, not as Administrator or LocalSystem.
11. Guest Agent artifact is verified on host and again inside guest before service creation/start.
12. Windows service readiness is not equivalent to Agent application/protocol health.
13. Bootstrap account retirement must be durably checkpointed before DPAPI state is discarded because retirement invalidates PowerShell Direct credentials.
14. A pairing URL/code is bootstrap authorization for a compatible HMS integration; ordinary ChatGPT does not gain shell access merely by receiving a URL.

## Security baseline

1. Deny by default.
2. No default ChatGPT path to the physical Windows host.
3. No implicit host-drive sharing.
4. Guest workspace access restricted to configured roots.
5. Normal HMS Agent work runs non-admin.
6. Destructive/privileged operations require explicit approval or exact managed-artifact policy where cleanup is security-critical and deterministic.
7. Host elevation is never implied by normal guest-control requests.
8. Reusable plaintext credentials must not appear in Git, pairing URLs or normal audit logs.
9. Pairing/session credentials are scoped, expiring, revocable and independently rotatable.
10. VM identity is pinned by VMId; identity conflicts fail closed.
11. Default NAT exposes no inbound guest management mapping.
12. `WillWipeDisk` is permitted only for the exact dedicated managed guest VHDX after destructive-target verification.
13. Unknown DVD media is not silently replaced or deleted.
14. Transient answer-media integrity is verified by SHA-256 before Windows Setup and again before local deletion.
15. Temporary bootstrap Administrator is disabled after Agent bootstrap; it is not the long-lived Agent identity.
16. AutoLogon password residue and managed unattend copies must be removed during retirement.
17. Agent binary directory is read/execute for the service SID; workspace/state are Modify only.

## Verification status

### Deterministic/code-level

The repository contains regression coverage for core Python models, generated XML/ISO/PowerShell invariants, PowerShell escaping, secret redaction, DPAPI platform behavior, package hashing, service-boundary configuration, bootstrap retirement and managed secret cleanup.

### CI visibility

The repository CI workflow now contains both Linux and Windows Python matrices. The connected GitHub status surface currently exposes no checks for the latest direct-push HEAD, and the workflow-run connector available in this chat only returns PR-triggered runs. Therefore **CI is currently pending/unobservable from this chat and is not declared PASS**.

### Not yet runtime PASS

A real Windows Hyper-V integration run is still mandatory. GitHub-hosted runners do not prove actual Hyper-V/vTPM/NAT/firmware behavior, Windows Setup answer-file consumption, PowerShell Direct bootstrap, Guest Service Interface copy semantics or real service SID ACL behavior on the target machine.

Do **not** label R002C runtime PASS until those Windows-host tests are executed and non-secret evidence is captured.

## Next objectives

### R002C Tranche 4B — persistent post-install finalization runtime

- extend durable provisioning state with guest-bootstrap/service-ready/bootstrap-retired/media-detached/secrets-cleared checkpoints;
- make crash/resume safe after bootstrap account disablement;
- require service readiness before retirement;
- require persisted retirement checkpoint before DPAPI deletion;
- add read-only post-reboot service proof;
- define actual Agent `/healthz` and capability schema;
- build/identify the real signed Agent executable artifact and package manifest generation path.

### R002C Tranche 3B/4C — real Windows/Hyper-V integration harness

- preflight Hyper-V/network/media conflicts;
- reconcile Internal vSwitch/NAT twice for idempotency proof;
- create VM, persist VMId, reconcile by VMId;
- prove Secure Boot + vTPM readback;
- run native DPAPI round-trip;
- start unattended Windows installation on an explicitly disposable test VM;
- prove PowerShell Direct, deterministic guest IP and Guest Service Interface copy;
- install Agent service and prove service SID ACLs;
- retire bootstrap account and clear install secrets;
- reboot and re-prove service readiness;
- capture deterministic non-secret evidence JSON;
- no broad/destructive cleanup of operator resources.

### R002C Tranche 5 — pairing/control proof

- one-time pair-token lifecycle;
- outbound authenticated Agent <-> Bridge session;
- compatible ChatGPT MCP/connector/action surface;
- `workspace.read`, `workspace.write`, `process.test`, `git.status`, `audit.read`;
- session rotation/revocation/idempotency;
- canonical end-to-end file proof.

## Canonical end-to-end target

ChatGPT, through the supported HMS control integration, creates `C:\HMS-Workspace\chatgpt-control-test.txt` inside the managed Windows VM, reads it back through the same authenticated path, and receives matching SHA-256, byte size, timestamp and audit event ID — without host filesystem sharing or host Administrator control.
