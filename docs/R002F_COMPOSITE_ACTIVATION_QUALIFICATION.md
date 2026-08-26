# R002F — Composite HMSBridge activation qualification

## Status

`STAGED_NOT_EXECUTED`

This checkpoint composes the existing HMSBridge activation/TLS qualification with the independent Secure MCP Tunnel native qualification without weakening either authority.

## One-generation qualification order

`qualify_hms_bridge_composite_activation_probe(...)` performs one exact stopped-to-running-to-stopped generation:

1. validate the existing secret-bearing activation request without exposing its fields;
2. load and validate the protected schema-v2 Bridge runtime config;
3. verify the pinned HMSBridge package and require exact Stopped/Manual service identity;
4. start HMSBridge through the existing activation start authority, which proves the service-owned TLS and loopback MCP listeners;
5. independently qualify the Secure MCP Tunnel child against the exact HMSBridge PID;
6. run the existing managed-Hyper-V guest TLS qualification;
7. independently qualify the tunnel again and require the same service PID, tunnel PID, parent PID, executable/hash, health attempt, health URL/listener and readiness class across the managed-guest probe;
8. stop HMSBridge through the existing bounded activation stop authority even when a qualification step fails;
9. require final exact Stopped/Manual service identity.

The composite result remains fail-closed and does not turn pairing or end-to-end command-flow flags true.

## Why this is separate from the older activation function

The older `qualify_hms_bridge_activation_probe(...)` remains intact as a narrower TLS/MCP qualification primitive. This checkpoint adds a stricter composite authority rather than rewriting the older function in place. A later runner-routing tranche must select the composite authority for R002F native activation qualification.

## Validation boundary

Synthetic pre-publication checks cover:

- exact successful ordering with two tunnel probes bracketing managed-guest TLS;
- tunnel process/generation drift rejection;
- tunnel qualification failure with mandatory service stop;
- managed-guest VM identity drift rejection;
- direct Python compilation with warnings-as-errors.

No Windows service, Hyper-V guest, DPAPI secret, tunnel process, socket or `/readyz` endpoint was executed here. Status remains `STAGED_NOT_EXECUTED`.
