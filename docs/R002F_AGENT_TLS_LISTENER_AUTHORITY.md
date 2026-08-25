# R002F Agent TLS Listener Authority

## Scope

This tranche adds the host-side TLS listener that carries the existing authenticated outbound-Agent HTTP protocol into `AgentBridgeHttpBoundary`.

It does **not** expose MCP, pairing, or control tools on the Hyper-V network and does not add any NAT static mapping or public listener.

## Network authority

The listener derives its bind and source authority from `HyperVNetworkConfig`:

- host bind IPv4 = exact managed internal-switch `gateway`;
- accepted peer IPv4 = exact managed `guest_ipv4`;
- the managed subnet must be RFC1918 private IPv4;
- `0.0.0.0`, loopback, link-local, multicast, public subnets, and a host/guest address collision fail closed.

With the canonical default network this is host `172.29.240.1`, guest `172.29.240.10`, port `9443`.

## TLS authority

`AgentBridgeTlsServer` accepts only a deployment-supplied `ssl.SSLContext` configured as `PROTOCOL_TLS_SERVER` with an explicit minimum of TLS 1.2 or newer. The listener does not generate certificates, private keys, or trust roots.

The deployment certificate must match the exact Agent `bridge_origin` hostname/IP under the Agent client's existing certificate and hostname verification rules. Loading and pinning deployment certificate/key material remains a separate deployment authority.

Every accepted TCP socket is source-checked, given a bounded request/handshake timeout, and TLS-wrapped before the HTTP request handler runs.

## HTTP framing authority

The listener preserves `BaseHTTPRequestHandler.headers.raw_items()` as raw header occurrences and passes them to `AgentBridgeHttpBoundary`; it never folds headers into a dict before duplicate-header validation.

Before body read it additionally requires:

- exactly one canonical decimal `Content-Length`;
- no `Transfer-Encoding`;
- non-empty body;
- body length no greater than `MAX_AGENT_BODY_BYTES`.

Connections are closed after each response, `Expect: 100-continue` is rejected, and listener error bodies are fixed secret-free JSON documents.

## Security boundaries retained

This tranche does not prove:

- Windows Firewall rule ownership for TCP/9443;
- a real certificate/key deployment or live TLS handshake;
- a real guest-to-host Agent hello/heartbeat/poll/result exchange;
- full Bridge command-flow qualification;
- re-pair lifecycle after control-session expiry;
- bootstrap retirement or final pairing readiness.

Until those proofs exist this source remains staged implementation, not production qualification evidence.
