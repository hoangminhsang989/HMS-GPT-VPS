# R002C Tranche 4 — Guest Bootstrap and Agent Boundary

Status: `FOUNDATION_IN_PROGRESS`

This document defines the authority for the post-Windows-install transition from the temporary Administrator bootstrap identity to the least-privilege HMS Agent Windows service.

## Security boundary

The temporary bootstrap Administrator exists only so the Windows host can use Hyper-V PowerShell Direct after unattended setup. It is not the long-term control identity and must not become the ChatGPT/HMS execution account.

The permanent execution boundary is:

`ChatGPT/HMS integration -> outbound authenticated Agent session -> HMSAgent Windows service -> C:\HMS-Workspace`

The host Hyper-V control plane remains separate and is not exposed through normal Agent capabilities.

## Tranche 4 foundation delivered

1. `powershell_direct.py`
   - `Invoke-Command -VMName` transport;
   - bootstrap username/password and guest script are passed only through the child PowerShell environment;
   - password is absent from the command line and generated host script;
   - child removes bootstrap environment variables before invoking the guest script.

2. `guest_bootstrap.py`
   - deterministic guest address `172.29.240.10/24`;
   - gateway `172.29.240.1` on the managed Internal NAT;
   - fail closed unless exactly one managed guest NIC is available;
   - creates `C:\HMS-Workspace` and runtime directories;
   - initial ACL is SYSTEM + Administrators only until the Agent service SID exists.

3. `vm_file_copy.py`
   - host artifact SHA-256 is verified before copy;
   - uses Hyper-V Guest Service Interface / `Copy-VMFile`, not SMB or host-drive sharing;
   - Guest Service Interface is enabled only for the copy window when necessary and restored in `finally`.

4. `agent_package.py`
   - immutable non-secret Agent manifest: filename, version, byte size and SHA-256;
   - local package verification fails closed on filename/size/hash mismatch.

5. `agent_service_install.py`
   - guest-side SHA-256 verification before SCM mutation;
   - service account is `NT AUTHORITY\LocalService`, never LocalSystem;
   - per-service SID `NT SERVICE\HMSAgent` is enabled with `sidtype unrestricted`;
   - Agent binary root receives Read/Execute only for the service SID;
   - workspace/state receive Modify for the service SID;
   - SYSTEM and Administrators retain Full Control;
   - failure recovery policy is configured before service start.

6. `agent_service_readiness.py`
   - read-only proof of SCM status, LocalService identity, command line, binary SHA-256, service SID type and filesystem rights;
   - returns `service_ready` only when every Windows service/ACL invariant passes;
   - explicitly reports `application_health = NOT_IMPLEMENTED` until the real Agent protocol `/healthz` exists.

7. `bootstrap_retirement.py`
   - disables the temporary local bootstrap user instead of deleting it;
   - disables AutoLogon and removes `DefaultPassword` residue;
   - removes only known cached unattend files whose content references the managed bootstrap username;
   - detaches only the exact managed answer ISO from Hyper-V;
   - no VM deletion, no DVD-drive deletion and no unrelated-media mutation.

8. `install_artifacts.clear_install_secrets()`
   - cleanup is scoped to the managed runtime directory;
   - an existing answer ISO must still match the persisted SHA-256 before deletion;
   - missing media is treated as already cleaned for crash/resume idempotency;
   - DPAPI state is cleared only after the managed-media check succeeds.

9. CI
   - Linux matrix remains Python 3.11/3.12/3.13;
   - Windows matrix now runs Python 3.11/3.12/3.13;
   - the existing DPAPI test performs a native protect/unprotect round-trip on Windows;
   - GitHub-hosted Windows runners do not prove nested Hyper-V runtime behavior.

## Required transition order

The production orchestration order is locked as:

1. Windows Setup completes.
2. Hyper-V heartbeat and PowerShell Direct readiness pass.
3. Guest network/workspace bootstrap passes.
4. Approved Agent package manifest is verified on host.
5. Agent executable is copied through Guest Service Interface.
6. Guest verifies Agent SHA-256.
7. HMSAgent service is installed/reconciled as LocalService + per-service SID.
8. Windows service-readiness probe passes.
9. **Future gate:** real Agent application `/healthz` and capability proof passes.
10. Bootstrap retirement is executed as the final credentialed PowerShell Direct action.
11. Successful retirement result is durably recorded before the DPAPI credential is discarded.
12. Managed answer ISO is detached.
13. Verified transient answer ISO and DPAPI record are deleted.
14. Normal control proceeds only through the Agent outbound authenticated channel.

Steps 9–14 must not be collapsed into an optimistic one-shot script. State must advance only after observed postconditions so a crash cannot silently skip credential/media cleanup.

## Runtime-PASS requirements still open

Tranche 4 is not runtime PASS until a real Windows Hyper-V host proves:

- PowerShell Direct login after unattended setup;
- deterministic guest IP/NAT connectivity;
- `Copy-VMFile` with Guest Service Interface state restoration;
- Agent executable copy and guest SHA-256 equality;
- LocalService service start;
- per-service SID ACL readback;
- Windows service-readiness result;
- actual Agent `/healthz` and capability report;
- bootstrap account disabled and AutoLogon residue absent;
- answer ISO detached;
- answer ISO + DPAPI transient secrets cleared;
- reboot confirms Agent service remains healthy without bootstrap credentials.

## Explicit non-claims

- The HMS Agent executable is not yet a completed production binary.
- `service_ready` is not equivalent to application protocol health.
- GitHub Windows CI is not a Hyper-V integration environment.
- No ordinary pasted URL grants ChatGPT shell access; Tranche 5 must provide a supported authenticated connector/MCP/Bridge control surface.
