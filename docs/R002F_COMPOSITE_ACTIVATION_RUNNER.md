# R002F — Composite HMSBridge activation qualification runner

## Status

`STAGED_NOT_EXECUTED`

This checkpoint stages the explicit Windows runner for the composite HMSBridge activation authority. It does not run the service, Hyper-V guest, Secure MCP Tunnel, or any production credential in this environment.

## Runner authority

The executable source is `scripts/qualify_hms_bridge_composite_activation.py`. It accepts only two non-secret path arguments:

- `--trust-root-certificate` — the managed-guest public trust-root PEM;
- `--proof` — a new create-only qualification proof path.

The managed-guest PowerShell Direct bootstrap credential is never accepted in argv. The runner deliberately reuses the existing R002E environment ingress names:

- `HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME`
- `HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD`

Both values are removed from the runner process environment with `pop()` when loaded. `PowerShellDirectCredential.password` remains `repr=False`.

## Execution contract

`run_composite_activation_qualification(...)`:

1. requires native Windows Administrator authority;
2. consumes the bootstrap credential from the existing environment ingress;
3. reads the public trust-root certificate through the pinned file-authority reader with a bounded size;
4. constructs the existing secret-hiding `BridgeActivationQualificationRequest`;
5. executes `qualify_hms_bridge_composite_activation_probe(...)`;
6. validates the exact composite result schema and proof boundary;
7. requires TLS, MCP, Secure MCP Tunnel, tunnel generation stability and managed-guest TLS evidence to be true;
8. requires HMSBridge to have returned to exact `Stopped` / `Manual`;
9. rejects any premature claim of authenticated Agent transport, full command flow, bootstrap retirement, pairing readiness or Automatic start;
10. publishes one bounded JSON proof with the existing create-only pinned publication authority.

The proof envelope is schema version `1` and identifies the qualification as `R002F_HMSBRIDGE_COMPOSITE_ACTIVATION`.

## CI separation

This runner is intentionally not added to `.github/workflows/bridge-native-scm.yml`. That workflow is a different authority: it proves that a freshly packaged HMSBridge fails closed when the fixed production runtime root/config is absent. It explicitly requires the production runtime root to be absent and therefore must not be converted into a production-secret/managed-guest activation gate.

A real composite activation run belongs on an already provisioned Windows/Hyper-V host with the exact reviewed production authorities. Until such a run occurs, the native CI fail-closed workflow and this activation runner remain separate proof classes.

## Validation boundary

Pre-publication synthetic validation:

- runner/library/script syntax compilation: PASS;
- secret environment consumption and `repr` exclusion regression: PASS;
- exact result-schema/proof-boundary regression: PASS;
- pinned trust-root -> composite probe -> create-only proof ordering regression: PASS;
- missing secret fail-closed regression: PASS;
- combined current service/tunnel/composite synthetic harness: 58/58 PASS.

Not executed here:

- repository-wide pytest from a real checkout;
- GitHub Actions for this branch;
- real Windows Administrator runner;
- real HMSBridge SCM activation;
- real Hyper-V PowerShell Direct credential;
- real Secure MCP Tunnel child/listener/`/readyz`;
- real managed-guest TLS;
- authenticated Agent transport;
- full ChatGPT -> tunnel -> MCP -> Bridge -> Agent command flow.

Status therefore remains `STAGED_NOT_EXECUTED`.
