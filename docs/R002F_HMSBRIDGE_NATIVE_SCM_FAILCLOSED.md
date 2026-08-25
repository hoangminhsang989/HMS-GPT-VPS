# R002F — Native HMSBridge SCM fail-closed qualification

Status: `STAGED_NOT_EXECUTED`

This tranche stages a Windows CI qualification for the packaged HMSBridge
service without provisioning production runtime configuration, OAuth secrets,
TLS material, firewall state, or Hyper-V guest state.

## Expected service transition

The packaged command is exactly:

`"<absolute hms-bridge.exe path>" service`

The temporary SCM service is:

- service name `HMSBridge`;
- account `NT SERVICE\HMSBridge`;
- own-process service;
- demand/Manual start;
- unrestricted service SID.

The fixed production runtime root
`C:\ProgramData\HMS-GPT-VPS\Bridge` must be absent before the probe and remain
absent afterward.

The service host assigns failure code `110` while proving the effective
HMSBridge token. Only after that strict identity proof returns does it set
failure code `120` for runtime construction. With production config
deliberately absent, the required final SCM observation is therefore:

- state `Stopped`;
- Win32 `ExitCode = 1066` (`ERROR_SERVICE_SPECIFIC_ERROR`);
- `ServiceSpecificExitCode = 120`;
- no listener on TCP port `9443`;
- no production runtime root created.

This proves the packaged executable attached to SCM, ran far enough for the
strict HMSBridge identity phase to complete, and then failed closed before
runtime/listener startup.

The probe is CI-only, requires an Administrator runner token, refuses to run
if `HMSBridge` or the fixed production Bridge root already exists, and deletes
only a temporary package root carrying a per-run ownership marker.

## Validation

Focused synthetic validator tests: `10 passed`.

This tranche does not claim a successful production Bridge startup. A
successful live qualification still requires the real protected runtime
config, LocalMachine-DPAPI OAuth credential, TLS material, firewall authority,
managed guest trust, authenticated Agent transport, and full command flow.
