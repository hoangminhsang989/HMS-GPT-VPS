# R002F — Production TLS deployment and live managed-guest qualification

Status: `STAGED_NOT_EXECUTED`

This checkpoint adds the next fail-closed authority after the private Hyper-V TLS listener and exact Windows Firewall rule.

## Scope

The implementation intentionally does **not** generate certificates. Production deployment must supply:

- one leaf certificate for the exact managed Bridge origin `https://172.29.240.1:9443`;
- the matching deployment-unlocked PEM private key on the host;
- one dedicated root CA certificate that is authorized to validate that leaf;
- canonical SHA-256 pins for the leaf DER, private-key file bytes, and root DER.

The host loader:

- requires regular, non-symlink/non-reparse certificate and key paths;
- pins certificate identity by DER SHA-256 and the private key by file SHA-256;
- checks file identity/content before and after `SSLContext.load_cert_chain`;
- creates only `ssl.PROTOCOL_TLS_SERVER` with minimum TLS 1.2;
- never generates or silently replaces TLS material.

The managed guest trust publication:

- is bound to the persisted Hyper-V `VMId` through PowerShell Direct;
- receives the exact root certificate as an in-memory payload rather than a command-line argument;
- requires a valid root CA certificate and adds only that exact pinned certificate to `LocalMachine\Root`;
- fails closed if a different root with the same subject is already present;
- never deletes or rewrites another trust anchor.

The live TLS qualification:

- originates inside the managed guest;
- opens TCP from the managed guest address to `172.29.240.1:9443`;
- uses `SslStream.AuthenticateAsClient("172.29.240.1")` with the Windows trust store and default chain/name validation;
- has no permissive certificate-validation callback;
- requires the observed local address to be `172.29.240.10`;
- requires the remote address/port to be `172.29.240.1:9443`;
- accepts only TLS 1.2 or TLS 1.3;
- pins the observed leaf certificate by DER SHA-256.

## Proof boundaries

This code does not claim that production TLS has run. Until real host/guest execution succeeds, all of the following remain false:

- Windows firewall rule executed on the real host;
- production certificate/key deployed on the real host;
- dedicated root CA installed in the real managed guest;
- live guest-to-host TCP/9443 reachability;
- live certificate-chain and hostname verification;
- authenticated Agent `hello` / `heartbeat` / `poll` / `result`;
- full Bridge command flow;
- re-pair lifecycle after control-session expiry;
- bootstrap retirement;
- pairing readiness.

A generated self-signed leaf or local mock handshake is not acceptable as production proof.

## Added authority

- `src/hms_gpt_vps/agent_bridge_tls_deployment.py`
- `tests/test_r002f_agent_bridge_tls_deployment.py`

Scratch validation before publication: module compilation plus 27 focused unit tests passed against minimal dependency stubs. This is **not** a substitute for the repository test suite, GitHub Actions, or real Windows/Hyper-V qualification.
