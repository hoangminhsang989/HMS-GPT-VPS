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

The loader uses pinned regular-file reading and rejects link/reparse traversal,
file-identity races, oversize input, invalid UTF-8, duplicate JSON keys, missing
fields, and unknown fields.

The config contains runtime identities, paths, ports and hashes only. It does
not contain Agent HMAC secrets, the pairing-exchange key, OAuth bearer tokens,
PowerShell Direct credentials, or the TLS private-key bytes.

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
that factory. The factory then re-proves identity, loads the fixed runtime
config, loads the production OAuth verifier, converts config to the already
reviewed production runtime types, and assembles the Bridge runtime.

This preserves the authority ordering:

`service SID resolve -> SCM identity proof -> fixed config -> OAuth verifier -> machine secrets -> production assembly -> listener readiness`

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

Synthetic/scratch validation before publication: 9/9 focused tests PASS and
direct Python syntax compilation PASS. These checks are not repository pytest,
GitHub Actions, packaging execution, native Windows SCM execution, or real
Hyper-V qualification.

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
