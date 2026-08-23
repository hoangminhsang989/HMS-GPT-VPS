# PROJECT STATE — HMS-GPT-VPS

## Current revision

R002C — Pairing/control security foundation (Tranche 5A)

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

`Tạo VPS -> detect/enable Hyper-V with approval -> resume after reboot -> verify Windows image -> ensure isolated Internal vSwitch/NAT -> create/recover identity-pinned Windows VM -> transient answer media -> unattended Windows install -> PowerShell Direct guest bootstrap -> copy/verify Agent artifact -> install least-privilege HMS Agent service -> prove Agent application health -> retire bootstrap Administrator -> detach answer media -> remove transient install secrets -> outbound authenticated Agent control -> one-time pairing -> scoped control session -> supported ChatGPT/HMS integration -> workspace/test/git operations inside the VM.`

Windows is the primary guest OS. Linux/WSL2 and remote VPS backends remain optional future modes.

## Delivered foundation

### R001

- fail-closed policy;
- workspace isolation;
- append-only audit;
- policy-gated executor;
- read-only Git operations;
- health CLI;
- unit tests and CI foundation.

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

### R002C Tranche 4 — guest bootstrap / Agent service boundary

- Windows CI matrix (`windows-latest`, Python 3.11/3.12/3.13) in addition to Linux matrix;
- existing DPAPI test executes a native protect/unprotect round-trip on Windows CI;
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
- bootstrap retirement primitive that disables (does not delete) the temporary account;
- AutoLogon disabled and `DefaultPassword` residue removed;
- cached unattend cleanup limited to known files whose content references the managed bootstrap username;
- exact managed answer-ISO detach primitive;
- transient install secret cleanup hardened to managed runtime path + persisted SHA-256;
- cleanup remains idempotent when answer ISO was already removed during crash/resume;
- regression tests for package tamper detection, service boundary, bootstrap retirement and managed secret cleanup;
- `docs/R002C_GUEST_BOOTSTRAP_AGENT.md`.

### R002C Tranche 4B — crash-safe finalization + application health

- `ProvisionState` explicitly separates `AGENT_SERVICE_READY` from `AGENT_HEALTHY`;
- durable post-install checkpoints: `BOOTSTRAP_RETIRING`, `BOOTSTRAP_RETIRED`, `ANSWER_MEDIA_DETACHED`, `INSTALL_SECRETS_CLEARED`;
- checked state transitions reject out-of-order cleanup;
- orchestrator no longer interprets SCM/service readiness as application protocol health;
- `AGENT_SERVICE_READY` waits for a real application-health proof before retirement;
- bootstrap retirement uses a two-phase fail-closed checkpoint: persist `BOOTSTRAP_RETIRING` before the final credentialed action;
- if the process dies in the retirement ambiguity window, automatic PowerShell Direct retry is forbidden and state remains `WAIT_FOR_BOOTSTRAP_RETIREMENT_PROOF`;
- a future authenticated Agent observation can provide external retirement proof without reusing the disabled bootstrap credential;
- host-side answer-media detach and secret cleanup remain idempotent/retriable after `BOOTSTRAP_RETIRED`;
- `PostInstallFinalizationRuntime` enforces state guards and verified cleanup order;
- strict Agent `/healthz` schema version 1;
- minimum application capability set: `workspace.read`, `workspace.write`, `process.test`, `git.status`, `audit.read`;
- health proof requires exact managed instance, exact workspace, `NT SERVICE\HMSAgent`, `loopback-only`, `non-admin`, unique capabilities and non-empty boot identity;
- health documents reject secret-bearing fields such as token/password/API key/authorization/cookie;
- local health probe is fixed to `http://127.0.0.1:<port>/healthz`, redirects disabled, executed through PowerShell Direct before bootstrap retirement;
- application-health and crash-recovery regression coverage.

### R002C Tranche 5A — pairing/control security foundation now adds

- one-time pairing grant with 256-bit random token;
- HTTPS-only pairing base URL and raw token in URL fragment `#token=...`, not query parameters;
- default pair TTL 10 minutes, maximum 30 minutes;
- pairing persistence stores token SHA-256 only;
- strict fail-closed parsing and temporal validation;
- exact canonical scope set: `workspace.read`, `workspace.write`, `process.test`, `git.status`, `audit.read`;
- SQLite `PairingStore` with serialized atomic consume/revoke behavior;
- post-pair `ControlSessionRecord` with independent token, exact instance/scopes, expiry, family and epoch;
- session token SHA-256 only at rest;
- atomic session rotation/revocation; rotation cannot expand scopes and old token dies after rotation;
- `ControlRequest` schema contains no authentication token and accepts only the five canonical actions;
- durable idempotency store with `CLAIMED -> COMPLETED` semantics;
- ambiguous crash after claim blocks automatic replay rather than repeating a possibly completed side effect;
- `ControlGateway` authenticates session + instance + scope before idempotency lookup/claim;
- unauthorized callers cannot retrieve a cached response by knowing a request ID;
- gateway audit excludes raw authentication token and request body parameters;
- `ControlActionRuntime` reuses R001 workspace/policy/executor/audit primitives instead of creating an unrestricted parallel executor;
- `workspace.read` bounded to 1 MiB with SHA-256/size/UTC modified proof;
- `workspace.write` bounded to 1 MiB, create-exclusive by default, approved replace requires exact `expected_sha256`;
- `.git` metadata writes are denied across case/separator/trailing-dot/space/ADS variants;
- no remote delete action exists in the current minimum control surface;
- `process.test` uses a fixed `python -m pytest` shape with bounded options and no arbitrary shell string;
- `git.status` is fixed read-only status command;
- `audit.read` is a bounded tail read;
- process/Git stdout and stderr are capped at 256 KiB each with truncation metadata;
- `TrustedLocalApproval` is absent from network request schema and binds exact request ID, instance, action, request SHA-256 and short lifetime;
- remote request parameters cannot self-approve destructive replace;
- `ControlService` composes authenticated gateway + idempotency + local approval + action runtime;
- in-process authenticated create -> replay -> read SHA-256 control proof exists;
- crash-safe pairing-to-initial-session exchange requires PairingStore and ControlSessionStore in one SQLite database and commits consume + exchange binding + initial session in one transaction;
- pairing exchange recovery is limited to 60 seconds and returns the same initial session rather than creating another;
- recovery is bound to the exact client-generated nonce; SQLite stores nonce SHA-256 only;
- initial session derivation is domain-separated HMAC using pair token + pair/instance identity + client nonce + Bridge root key;
- pair token alone is insufficient to derive/recover the initial session without both the nonce and Bridge root key;
- wrong nonce, wrong Bridge key, expired recovery window or changed/rotated initial session fails closed;
- `PairingExchangeKeyStore` persists the Bridge root key with current-user Windows DPAPI by default;
- Bridge root-key publication is create-once: fsynced temporary ciphertext + create-only hard-link, never silent overwrite;
- corrupt/unprotectable existing root-key file is never silently regenerated;
- native Windows DPAPI key-store regression plus injected cross-platform/concurrent create tests added;
- `docs/R002C_PAIRING_CONTROL.md` is the Tranche 5 control authority.

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
13. Bootstrap account retirement has an explicit ambiguity checkpoint (`BOOTSTRAP_RETIRING`); automatic credential reuse is forbidden once that checkpoint exists.
14. DPAPI state is not discarded until retirement is proven and answer media has been detached.
15. Agent application health must be secret-free, loopback-only for local health probing and prove non-admin capability readiness.
16. A pairing URL/code is bootstrap authorization for a compatible HMS integration; ordinary ChatGPT does not gain shell access merely by receiving a URL.
17. Pairing credentials and long-lived control-session credentials are separate lifecycles.
18. Pairing-to-initial-session creation is one atomic database transaction; bounded crash recovery must never create a second initial session.
19. Pairing crash recovery requires the original client nonce in addition to the pair token; only the nonce digest is persisted.
20. The persistent Bridge exchange root key is DPAPI-protected and create-once; silent rotation/regeneration is forbidden.
21. Session authorization occurs before idempotency response lookup.
22. Network requests cannot self-approve destructive operations; trusted local approval is an out-of-band local boundary.
23. Remote workspace write permission does not include Git metadata mutation or deletion.
24. An unresolved idempotency claim is an ambiguity gate, not permission to retry a side effect automatically.

## Security baseline

1. Deny by default.
2. No default ChatGPT path to the physical Windows host.
3. No implicit host-drive sharing.
4. Guest workspace access restricted to configured roots.
5. Normal HMS Agent work runs non-admin.
6. Destructive/privileged operations require explicit trusted approval or exact managed-artifact policy where cleanup is security-critical and deterministic.
7. Host elevation is never implied by normal guest-control requests.
8. Reusable plaintext credentials must not appear in Git, normal state, SQLite databases or normal audit logs.
9. Pairing/session credentials are scoped, expiring, revocable and independently rotatable.
10. VM identity is pinned by VMId; identity conflicts fail closed.
11. Default NAT exposes no inbound guest management mapping.
12. `WillWipeDisk` is permitted only for the exact dedicated managed guest VHDX after destructive-target verification.
13. Unknown DVD media is not silently replaced or deleted.
14. Transient answer-media integrity is verified by SHA-256 before Windows Setup and again before local deletion.
15. Temporary bootstrap Administrator is disabled after Agent application health is proven; it is not the long-lived Agent identity.
16. AutoLogon password residue and managed unattend copies must be removed during retirement.
17. Agent binary directory is read/execute for the service SID; workspace/state are Modify only.
18. Agent `/healthz` may contain no reusable authentication material.
19. A crash during bootstrap retirement must fail closed rather than attempt blind credential reuse.
20. Raw pair token, session token, exchange nonce and Bridge exchange root key must not be stored in control SQLite.
21. Pairing exchange root key ciphertext must remain outside Git/source workspace and be protected by current-user DPAPI on Windows.
22. Completed idempotent requests may replay cached results; unresolved claims block automatic replay.
23. `.git` metadata is outside current remote `workspace.write` authority.
24. Destructive replace requires local approval plus an exact existing-content SHA-256 precondition.

## Verification status

### Deterministic/code-level

The repository now contains regression coverage for core provisioning models, generated XML/ISO/PowerShell invariants, PowerShell escaping, secret redaction, DPAPI platform behavior, package hashing, service-boundary configuration, application-health schema, retirement crash handling, pairing/token state, atomic pairing-session exchange, nonce-bound recovery, protected Bridge exchange-key persistence, session rotation/revocation, request authorization/idempotency, trusted local approval and the five minimum control actions.

A unit/in-process control proof creates a workspace file, replays the same request idempotently, reads the file back through the authenticated control service, and verifies matching SHA-256/size while checking that raw session token and file content are not written to normal audit output.

This is not equivalent to a real VM/Agent/network proof.

### CI visibility

The repository CI workflow contains both Linux and Windows Python matrices. The connected GitHub status surface has not exposed direct-push checks in this chat, so **CI is not declared PASS unless a visible check result is obtained**.

### Not yet runtime PASS

A real Windows Hyper-V integration run remains mandatory. GitHub-hosted runners do not prove actual Hyper-V/vTPM/NAT/firmware behavior, Windows Setup answer-file consumption, PowerShell Direct bootstrap, Guest Service Interface copy semantics, service SID ACL behavior, the real HMS Agent executable, outbound Agent transport, Bridge network endpoints or a supported ChatGPT connector on the target machine.

Do **not** label R002C runtime PASS until those Windows-host and integration tests are executed and non-secret evidence is captured.

## Next objectives

### R002C Tranche 5B — Agent device identity + outbound transport

- define a persistent per-Agent device identity separate from user pairing/session credentials;
- protect Agent/Bridge device credentials at rest;
- implement outbound-only authenticated Agent -> Bridge connection with TLS;
- bind connection to exact managed `instance_id`, Agent boot identity and capability set;
- heartbeat/presence/reconnect with monotonic connection epoch;
- reject stale/superseded Agent connections;
- define command/response envelope with request ID, deadline and bounded payloads;
- route control requests through the real Agent rather than executing only in the in-process test runtime;
- preserve idempotency and local approval semantics across network disconnects.

### R002C Tranche 4C — real Agent executable + Windows/Hyper-V integration

- build/identify the real HMS Agent Windows executable artifact;
- implement loopback-only `/healthz` schema v1 in that executable;
- implement the five minimum non-admin capabilities behind the Agent policy boundary;
- verify package manifest + guest SHA-256 + service install on real Windows;
- execute the full unattended install/bootstrap/finalization path on an explicitly disposable Hyper-V VM;
- prove restart persistence and post-reboot Agent health;
- capture deterministic non-secret evidence JSON;
- no broad/destructive cleanup of operator resources.

### R002C Tranche 5C — Bridge endpoints + supported ChatGPT integration

- expose network pairing/session/control endpoints over TLS;
- ensure access/request logs redact or omit all reusable credentials and exchange nonces;
- implement supported ChatGPT MCP/connector/action surface for the five canonical capabilities;
- bind ChatGPT-side session to exact managed instance and scopes;
- exercise rotation/revocation/idempotency through the real connector;
- canonical real-VM file proof.

## Canonical end-to-end target

ChatGPT, through the supported HMS control integration, creates `C:\HMS-Workspace\chatgpt-control-test.txt` inside the managed Windows VM, reads it back through the same authenticated Agent control path, and receives matching SHA-256, byte size, timestamp and audit event ID — without host filesystem sharing or physical-host Administrator control.
