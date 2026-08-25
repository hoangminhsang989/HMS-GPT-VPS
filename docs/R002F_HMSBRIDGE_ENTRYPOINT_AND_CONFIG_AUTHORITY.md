# R002F — HMSBridge entrypoint and fixed runtime-config authority

Status: `STAGED_NOT_EXECUTED`

This checkpoint creates the real executable entry path expected by the staged
SCM authority without weakening the existing privilege split.

## Executable authority

The product command is now:

`hms-bridge service`

The PyInstaller source entry is `scripts/hms_bridge_entry.py`, matching the
staged SCM expectation that the packaged binary is `hms-bridge.exe` and the
SCM command line is exactly `"<pinned hms-bridge.exe>" service`.

The `service` command accepts no config-path override, OAuth token, guest
credential, provisioning credential, private-key path, or other secret-bearing
argument.

## Fixed config authority

The service runtime config is fixed to:

`C:\ProgramData\HMS-GPT-VPS\Bridge\bridge-runtime.json`

Schema version: `1`
Maximum size: `64 KiB`

The parser rejects invalid UTF-8, duplicate JSON keys, missing fields, unknown
fields, noncanonical hashes, invalid pairing/readiness bounds and path traversal
segments.

The config contains runtime identities, paths, ports and hashes only. It does
not contain Agent HMAC secrets, the pairing-exchange key, OAuth bearer tokens,
PowerShell Direct credentials, or the TLS private-key bytes.

## Exact config storage ACL authority

The service entrypoint does not use the raw parser/reader directly. Its default
loader is `load_protected_bridge_service_runtime_config(...)`.

The fixed ProgramData Bridge directory and `bridge-runtime.json` must have
protected, non-inherited ACLs owned by `BUILTIN\Administrators` with exactly:

- `SYSTEM`: FullControl;
- `BUILTIN\Administrators`: FullControl;
- exact `NT SERVICE\HMSBridge` SID: ReadAndExecute on the directory and Read on
  the config file (with the canonical Windows Synchronize bit).

No broad Users/Authenticated Users write path is accepted. Reparse points are
rejected.

The read-only service loader performs:

`ACL/SHA proof -> pinned exact-byte read -> SHA comparison -> strict parse -> ACL/SHA re-proof`

If config bytes, ACLs, owner, path authority or service SID differ across that
boundary, startup fails closed. A separate privileged
`provision_bridge_service_runtime_config_storage(...)` reconciler exists for
the provisioning/controller phase; the low-privilege service path uses proof
only.

## Network authority is not configurable

The runtime config deliberately contains no subnet, gateway, guest IPv4 or
Hyper-V switch override. Conversion always constructs the canonical
`HyperVNetworkConfig()` authority:

- switch: `HMS-GPT-VPS-Internal`
- subnet: `172.29.240.0/24`
- host gateway: `172.29.240.1`
- managed guest IPv4: `172.29.240.10`

The Agent TLS origin is derived from the fixed gateway and configured TLS port;
it is not accepted as caller-controlled config text.

The machine-scope service-secret root is likewise derived as
`<runtime_root>\secrets\service-runtime`; the config cannot redirect the secret
store elsewhere.

## Identity-before-config ordering

`run_hms_bridge_service_entrypoint()` performs only a non-secret resolution of
the deterministic `NT SERVICE\HMSBridge` SID before entering the SCM host. It
passes a lazy runtime factory to `HmsBridgeWindowsServiceHost`.

The SCM host proves the effective low-privilege service token before invoking
that factory. The factory then re-proves identity, performs the protected fixed
config load, loads the production OAuth verifier, converts config to the already
reviewed production runtime types, and assembles the Bridge runtime.

This preserves the authority ordering:

`service SID resolve -> SCM identity proof -> config ACL/SHA proof -> fixed config -> OAuth verifier -> machine secrets -> production assembly -> listener readiness`

## OAuth verifier gate remains closed

A production `TokenVerifier` authority has not yet been frozen in R002F. The
default verifier loader therefore raises:

`production OAuth token verifier authority is not provisioned`

No accept-all verifier, unsigned JWT path, development token, or self-attested
authentication fallback is introduced by this checkpoint. The staged service
is still intentionally non-runnable until the next authentication-authority
tranche supplies a reviewed verifier loader.

## Packaging

`pyproject.toml` exposes both console scripts:

- `hms-agent = hms_gpt_vps.cli:main`
- `hms-bridge = hms_gpt_vps.bridge_cli:main`

The separate `scripts/hms_bridge_entry.py` is retained as the explicit
PyInstaller entry source for the future pinned `hms-bridge.exe` artifact.

## Validation boundary

The pre-publication entrypoint/config candidate passed 9/9 synthetic focused
checks plus direct Python syntax compilation. Additional regression tests for
the exact config ACL/SHA sandwich are committed with this checkpoint.

A later attempt to obtain an independent repository checkout for full pytest
could not resolve `github.com` from the execution container. Therefore this
checkpoint does **not** claim repository pytest, GitHub Actions, packaging
execution, native Windows SCM execution, or real Hyper-V qualification.

The following remain false:

- production OAuth verifier authority provisioned
- `hms-bridge.exe` packaged and SHA-256 pinned on a real host
- real HMSBridge SCM execution
- real Agent TLS listener proof
- real loopback MCP startup proof
- authenticated Agent transport proof
- full Bridge command-flow proof
- bootstrap retirement
- pairing readiness

PR #11 remains outside this checkpoint and must not be merged from it.
