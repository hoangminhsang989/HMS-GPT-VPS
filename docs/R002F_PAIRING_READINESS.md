# R002F Pairing Readiness and Recoverable Link Lease

Status: **STAGED_NOT_EXECUTED**

Parent authority: `55cf8c9a04c555ae6595185d62aa1528f84336ea`
Branch: `r002f-pairing-readiness-runtime`

## Purpose

R002F begins Stage 3: Pairing & Secure Control Channel. The transport protocol,
outbound HTTPS Agent session, Bridge HMAC authentication, command queue,
one-time pairing contract, exchange handshake and control policy already exist.
This tranche fills the missing orchestration boundary between provisioning state,
authenticated Agent presence and the user-visible **Sao chép liên kết** action.

## Product rule

A pairing link may be issued only when all of the following are true:

1. durable provisioning state is `INSTALL_SECRETS_CLEARED` or
   `PAIRING_PENDING`;
2. the Bridge has authenticated presence for the exact `instance_id`;
3. the presence is fresh;
4. there is one recoverable encrypted link lease and one matching digest-only
   pairing record.

The default presence freshness bound is 90 seconds. This is three times the
current 30-second Agent heartbeat interval, not a claim that a disconnected
Agent is healthy indefinitely.

## Crash-safe ordering

The raw one-time token must never be written to PairingStore SQLite. The
encrypted host lease is written first:

1. generate one `PairingGrant`;
2. persist `PairingLinkLease` through current-user DPAPI;
3. re-check provisioning state and fresh Agent presence;
4. create the digest-only `PairingStore` record;
5. read back and compare immutable record authority;
6. return the copyable link.

If the host process dies after step 2 but before step 4, the next call reloads
the encrypted lease and creates the exact missing digest record. It does not
mint a replacement token. If the process dies after step 4 but before the UI
receives the link, the same encrypted lease reconstructs the same link.

## Observation contract

The runtime does not mutate provisioning state.

- active record + fresh authenticated Agent:
  `pairing_ready=true`, `paired=false`;
- consumed record + fresh authenticated Agent:
  `pairing_ready=true`, `paired=true`;
- no lease, missing record, stale/missing presence, revoked or expired active
  grant:
  readiness remains false.

The existing `ProvisioningOrchestrator` remains the only owner of
`INSTALL_SECRETS_CLEARED -> PAIRING_PENDING -> READY` advancement.

## Secret handling

`PairingLinkLease` stores the initial immutable PairingRecord plus raw token and
copyable link. Token and link fields are `repr=False`. Production construction
reuses the pinned current-user DPAPI file mechanics already used for R002E
transfer-token storage. PairingStore continues to hold only token SHA-256.

The lease is intentionally retained through pairing consumption until a later
lifecycle tranche can prove that provisioning state reached READY and can retire
the encrypted copy without introducing a crash window.

## Concurrency

Issuance runs under `exclusive_authority_lock`. Cooperating host processes
therefore cannot independently mint competing grants for the same configured
pairing authority.

## Remaining trust-boundary work

This tranche deliberately does **not** claim production pairing proof yet.

The follow-up SQLite-authority revision in this branch additionally hardens:

- `PairingRecord` parsing to exact schema/type semantics with no `int()`/`str()`
  coercion of stored authority;
- `PairingStore` to preserve lexical database authority, reject
  symlink/junction/reparse redirects, pin the startup database file identity
  across later operations, reject malformed/duplicate stored JSON, and use
  bounded exact timeout configuration;
- `AgentConnectionRegistry` with the same lexical/stable database identity
  discipline plus exact stored presence types, finite timestamps and epoch
  validation.

Before production qualification, remaining work includes:

- Bridge HTTP endpoint assembly for `/pair/<pair_id>` and control-session
  exchange;
- real Agent -> Bridge HTTPS connectivity on a managed Hyper-V guest;
- actual user copy/paste pairing-link exchange and one bounded command.

No real VM or Bridge session was executed by this staging revision.

Therefore project authority remains:

- `hyperv_guest_proven=false`
- `full_bridge_command_flow_proven=false`
- `bootstrap_retired=false`
- `pairing_ready=false`

No R002E merge gate is weakened by R002F staging.

## Control-session and exchange authority hardening

Before HTTP assembly, R002F also treats the initial control session as credential
authority rather than trusting legacy coercive SQLite reads.

The staged revision requires:

- `ControlSessionRecord` exact field/type parsing, canonical lowercase token
  digests and exact integer TTL/epoch semantics;
- `ControlSessionStore` lexical main-database authority with
  symlink/junction/reparse rejection, startup file-identity pinning, bounded
  timeout configuration, duplicate-JSON rejection and guaranteed connection
  close even when SQLite setup fails;
- exact agreement between duplicated SQLite identity columns and the canonical
  stored session record;
- `PairingSessionExchange` to stop opening an independent unchecked SQLite
  connection. Exchange transactions reuse PairingStore's hardened connection
  authority and cross-check that PairingStore and ControlSessionStore refer to
  the exact same startup database object;
- exchange recovery rows to use exact pair/session identities and canonical
  nonce SHA-256 text, without `str()` coercion.

This still does not make the HTTP pairing endpoint production-ready. The next
bounded tranche is the HTTP adapter itself, including bounded request bodies,
exact path/JSON contracts, generic non-secret error responses and one-time
pairing-to-session exchange semantics.

All source and regression checks performed while staging this revision are
static/synthetic unless an actual project CI run is cited separately.
