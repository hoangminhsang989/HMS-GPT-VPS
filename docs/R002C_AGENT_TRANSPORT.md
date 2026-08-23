# R002C Agent Device Identity and Outbound Transport Authority

Status: `FOUNDATION_IN_PROGRESS`

This document defines the R002C Tranche 5B Agent-device identity and outbound transport contract. It is code-level authority only. It does **not** declare a real Windows Hyper-V Agent/Bridge/TLS/ChatGPT end-to-end runtime PASS.

## 1. Boundary

The Agent transport identity is separate from user pairing and user control-session credentials.

Permanent control topology:

`supported ChatGPT/HMS integration -> Bridge user/session auth -> Bridge Agent transport -> outbound authenticated HMS Agent -> policy-gated action -> C:\HMS-Workspace`

The Windows guest opens no default inbound management port for ChatGPT. PowerShell Direct remains a temporary bootstrap/finalization mechanism only.

## 2. Agent device credential

`AgentDeviceCredential` contains:

- exact managed `instance_id`;
- random `device_id`;
- independent 32-byte device secret.

The device secret is not a user session token, not a pairing token and not a Bridge pairing-exchange root key.

A provisioning retry must reuse the existing credential for the same managed instance. Silent device-id/secret rotation is forbidden.

## 3. Credential protection at rest

### Bridge copy

`BridgeAgentDeviceCredentialStore` protects the trusted Bridge copy with current-user Windows DPAPI.

Properties:

- create-only publication;
- existing conflicting credential is never overwritten;
- exact instance/device identity can be required on load;
- file contains a non-secret format marker plus protected payload only;
- secret is excluded from dataclass repr;
- raw secret is not stored in SQLite or normal audit output.

### Guest copy

`GuestAgentDeviceCredentialStore` uses LocalMachine DPAPI because the credential is provisioned under a bootstrap identity but later consumed by the `LocalService` Agent on the same guest.

Machine-scope DPAPI is encryption, not authorization. The State-directory ACL remains mandatory.

The intended guest path is:

`C:\ProgramData\HMS-GPT-VPS\State\agent-device-credential.dpapi`

The service installer maintains the State ACL for:

- `SYSTEM`: Full Control;
- `Administrators`: Full Control;
- `NT SERVICE\HMSAgent`: Modify after the service identity exists.

## 4. Secure pre-service enrollment

`AgentDeviceEnrollmentConfig` and `enroll_agent_device()` implement the bootstrap enrollment boundary.

Locked order:

1. load the existing Bridge credential for the exact instance, or create it once;
2. serialize only a short bounded enrollment payload;
3. pass that payload through the PowerShell Direct child-process environment, not command-line text or host-script text;
4. remove the environment variable before `Invoke-Command`;
5. inside the guest, require the already-protected HMS runtime parent;
6. create/reconcile the State directory ACL before every credential read/write;
7. protect the credential with LocalMachine DPAPI;
8. publish the credential file create-only;
9. on a publication race, accept only an existing file that decrypts to the exact same instance/device/secret;
10. return only non-secret instance/device/path proof.

The guest script validates exact payload fields and exact protected-credential fields. Unknown fields, wrong instance, wrong device, wrong secret length, corrupt DPAPI content or ACL failure fail closed.

## 5. Durable provisioning gate

The existing `ProvisionState.AGENT_INSTALLING` state is now used as the durable proof checkpoint for completed device enrollment; no state-schema migration is required.

Required sequence:

`GUEST_BOOTSTRAP`

- if `agent_device_enrolled == false`: action `ENROLL_AGENT_DEVICE`, remain in `GUEST_BOOTSTRAP`;
- if `agent_device_enrolled == true`: persist `AGENT_INSTALLING` with reason `agent_device_enrollment_verified`.

Only from `AGENT_INSTALLING` may the orchestrator issue `INSTALL_HMS_AGENT`.

Therefore a crash/retry cannot intentionally skip device enrollment and jump directly from guest bootstrap to service installation.

## 6. Outbound Agent request authentication

`agent_transport_protocol.py` defines the code-level outbound request contract.

Allowed Agent endpoints are fixed to:

- `/agent/v1/hello`
- `/agent/v1/heartbeat`
- `/agent/v1/poll`
- `/agent/v1/result`

Requests are HMAC-SHA256 authenticated and bind at least:

- HTTP method and fixed path;
- `device_id`;
- `instance_id`;
- Agent `boot_id`;
- monotonic `connection_epoch`;
- timestamp;
- random request nonce;
- request-body SHA-256.

Additional locked bounds:

- maximum Agent body: 2 MiB;
- maximum accepted clock skew: 90 seconds;
- no arbitrary outbound endpoint path in the protocol contract.

## 7. Presence, replay and connection epoch

`AgentConnectionRegistry` persists Bridge-side connection/presence state in SQLite.

The Bridge verifies the request HMAC before a request can claim a nonce or mutate connection state.

Nonce claim and connection transition are serialized in one `BEGIN IMMEDIATE` transaction.

Fail-closed rules include:

- duplicate nonce rejected;
- lower/stale connection epoch rejected;
- same epoch with a different boot identity rejected;
- another device attempting to own the same managed instance rejected;
- a higher epoch may supersede an older valid connection for the same device/instance according to the registry contract.

## 8. Bridge command envelope

Bridge-to-Agent commands are separately signed with the Agent device credential.

The command envelope binds:

- schema version;
- request ID;
- exact instance ID;
- one of the minimum supported actions;
- canonical parameters;
- timezone-aware deadline;
- optional exact approved-command SHA-256 when approval semantics require it.

A supplied approved-command hash must match the canonical command hash exactly.

Expired, malformed, wrong-instance or bad-signature commands fail closed.

## 9. Separation from pairing/control plane

`docs/R002C_PAIRING_CONTROL.md` remains the authority for:

- one-time pairing;
- user control sessions;
- session scope/rotation/revocation;
- request idempotency;
- trusted local destructive approval;
- minimum action runtime.

This document remains the authority for the machine/device leg between Bridge and HMS Agent.

User/session credentials are never substituted for Agent device credentials, and Agent device credentials do not grant a ChatGPT user session by themselves.

## 10. Code-level verification present

Regression coverage now includes:

- current-user and LocalMachine DPAPI primitives;
- Bridge and guest device credential create-only stores;
- raw-secret exclusion from protected files/repr;
- wrong-instance/wrong-device/wrong-scope/corrupt-store rejection;
- concurrent first-publication convergence;
- env-only PowerShell Direct secret payload and payload bounds;
- stable Bridge `load-or-create` behavior across provisioning retries;
- secure enrollment payload and non-secret guest script;
- exact guest enrollment response identity validation;
- State ACL retry reconciliation and preservation of the service SID when present;
- durable `GUEST_BOOTSTRAP -> AGENT_INSTALLING` enrollment gate;
- Agent HMAC protocol validation, body/path/time bounds and command signatures;
- nonce replay, stale epoch, boot conflict and device conflict rejection.

## 11. Explicitly not yet runtime PASS

The following evidence is still mandatory:

- native target-Windows proof that bootstrap identity can LocalMachine-DPAPI protect the guest credential and `NT AUTHORITY\LocalService`/`NT SERVICE\HMSAgent` can later decrypt it under the managed ACL;
- real `hms-agent.exe` loading the credential and running non-admin;
- real outbound HTTPS/TLS Agent -> Bridge network client;
- real Bridge `/agent/v1/*` endpoint runtime wired to HMAC verification and `AgentConnectionRegistry`;
- reconnect/heartbeat/poll/result soak and network fault recovery;
- command delivery from Bridge to real Agent and result return;
- real Hyper-V VM file create/read proof through that network path;
- supported ChatGPT connector/MCP/action integration;
- visible CI result for the current direct-push HEAD;
- target Windows Hyper-V integration evidence.

Do not label Tranche 5B or R002C runtime PASS until these proofs exist.

## 12. Next implementation order

1. implement the actual outbound HTTPS Agent client loop using the existing protocol contract;
2. implement Bridge Agent endpoints that authenticate before presence/replay mutation;
3. wire hello/heartbeat/poll/result to the connection registry;
4. wire signed Bridge commands to `ControlActionRuntime` inside the real Agent service;
5. add reconnect/backoff/epoch persistence and bounded command/result queues;
6. perform native Windows LocalService credential-decrypt proof;
7. perform real Hyper-V Agent <-> Bridge end-to-end proof;
8. connect the supported ChatGPT integration only after the machine-control leg is proven.
