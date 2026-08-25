# R002F — HMSBridge Windows SCM virtual-account authority

Status: `STAGED_NOT_EXECUTED`

This checkpoint stages the long-lived host Bridge identity without starting the production service.

## Frozen service authority

- Service name: `HMSBridge`.
- Virtual account: `NT SERVICE\HMSBridge`.
- Service SID: deployment-pinned `S-1-5-80-...` value resolved back from the virtual account after SCM creation.
- SCM type: own process.
- Stage start mode: Manual / demand.
- Command: exact quoted deployment-pinned `hms-bridge.exe service`.
- Executable bytes: canonical SHA-256 pinned before and after SCM mutation.
- Symlink/junction/reparse traversal: rejected.
- Service is never started by the staging operation.
- The staging code contains no Administrators or Hyper-V Administrators membership mutation.

Microsoft documents virtual service accounts as `NT SERVICE\<SERVICENAME>` accounts with no password-management requirement. The production runtime still treats the effective token, not SCM text, as the authorization boundary.

## Runtime identity gate

Before constructing any runtime object that may read secrets or TLS material, the SCM host proves:

- token user SID exactly equals the deployment-pinned `HMSBridge` service SID;
- the user SID is a dedicated `S-1-5-80-...` service SID;
- identity name is exactly `NT SERVICE\HMSBridge`;
- Builtin Administrators SID `S-1-5-32-544` is absent from the token;
- Hyper-V Administrators SID `S-1-5-32-578` is absent from the token.

This preserves the R002F privilege split: Hyper-V / PowerShell Direct operations remain external privileged provisioning and qualification work; the long-lived Bridge does not receive those rights.

## Deliberate staging boundary

The service remains `Manual` and `Stopped`. No `hms-bridge` CLI/packaged executable is published by this checkpoint because the production secret/dependency loader is not yet complete. Publishing an auto-starting service before that loader exists would create a false readiness claim.

The following remain false:

- real host `HMSBridge` SCM execution proof;
- real `HMSBridge` token proof;
- production secret loader proof;
- live managed-guest TLS proof;
- authenticated Agent transport proof;
- full Bridge command flow proof;
- bootstrap retired;
- pairing ready.

## Next required trust boundary

Existing host Bridge pairing-exchange/device-credential stores use current-user DPAPI. They are not a valid cross-identity production authority for a privileged provisioning process and the `NT SERVICE\HMSBridge` runtime. The next tranche must introduce distinct LocalMachine-DPAPI service stores behind exact filesystem ACLs (SYSTEM/Administrators administration plus HMSBridge read authority) and a production dependency loader. Legacy current-user stores must not be silently migrated or reinterpreted.
