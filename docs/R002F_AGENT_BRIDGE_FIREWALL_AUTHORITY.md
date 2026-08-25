# R002F Agent Bridge Firewall Authority

## Scope

This tranche adds the Windows Firewall reconcile authority required for the private Hyper-V Agent TLS listener.

It owns only one local persistent inbound rule named `HMS-GPT-VPS Agent Bridge TLS`.

## Exact rule

Canonical defaults:

- direction: Inbound;
- action: Allow;
- enabled: True;
- profile: Any;
- protocol: TCP;
- local port: 9443;
- remote port: Any;
- local address: `172.29.240.1`;
- remote address: `172.29.240.10`;
- interface alias: `vEthernet (HMS-GPT-VPS-Internal)`;
- edge traversal: Block;
- policy store source: Local persistent policy.

`Profile Any` is intentional. Reachability is constrained by the exact Hyper-V internal interface plus exact local and remote IPv4 authorities, so the rule does not apply to physical/LAN interfaces and does not depend on mutable Windows NLA profile classification.

## Fail-closed ownership

If no same-name rule exists, the reconciler creates the exact rule and re-observes it.

If a same-name rule already exists, there must be exactly one and every observed authority field must match. A conflicting rule is not deleted, widened, or rewritten automatically; reconciliation fails instead.

Wildcard switch aliases are rejected before script generation.

## Security boundaries retained

This tranche does not prove:

- actual execution of `New-NetFirewallRule` on a Windows Hyper-V host;
- a live TCP/9443 reachability probe from the managed guest;
- certificate/key deployment or a successful TLS handshake;
- authenticated Agent hello/heartbeat/poll/result over the live listener;
- full Bridge command-flow qualification;
- re-pair lifecycle after session expiry;
- bootstrap retirement or final pairing readiness.

Until those proofs exist, the firewall code is staged implementation only.
