# R002F — Private-key storage authority and production TLS orchestration

Status: `STAGED_NOT_EXECUTED`

This checkpoint closes the next host-side trust boundary after production TLS material loading and managed-guest TLS qualification.

## Private-key storage authority

The private key must live as the only entry in one dedicated storage directory.

The provisioning authority:

- rejects symlink/reparse traversal for both the storage root and private key;
- requires the key to be a direct child of the dedicated root;
- pins the private-key file bytes by canonical SHA-256 before and after ACL reconciliation;
- protects both directory and file DACLs from inheritance;
- permits only three explicit principals:
  - `SYSTEM` (`S-1-5-18`) — FullControl;
  - `BUILTIN\Administrators` (`S-1-5-32-544`) — FullControl;
  - one configured dedicated `NT SERVICE` SID (`S-1-5-80-...`) — ReadAndExecute on the directory and Read on the key;
- rejects broad principals such as Everyone, Authenticated Users, Users, Guests and non-service reader SIDs;
- never deletes, moves, replaces or rewrites private-key bytes.

`ensure_agent_bridge_private_key_storage` is a provisioning/reconciliation operation. The production runtime additionally proves that its inherited Windows token is the exact configured service SID and requires the storage operation to report `changed=false`. Therefore an interactive administrator process cannot use the production orchestration path as the Bridge runtime.

## Production TLS orchestration

`start_agent_bridge_production_tls` composes the previously separate fail-closed authorities in one ordered runtime gate:

1. prove exact dedicated Bridge service SID;
2. require already-converged private-key storage ACL authority;
3. load the SHA-256-pinned certificate/private-key pair;
4. prove/create the exact host firewall rule;
5. start the TLS listener on exactly `172.29.240.1:9443`;
6. install the pinned root CA into the exact VMId-bound managed guest;
7. prove a live trusted guest-to-host TLS handshake;
8. re-check the listener bind authority after the guest proof.

If any step after listener start fails, the listener is shut down. The firewall rule or already-published root CA are not silently removed because those are independently idempotent authorities and removal would cross a separate destructive boundary.

## Proof boundary remains closed

This checkpoint does not prove that the Windows/Hyper-V production path has run. Until real execution succeeds, the following remain false:

- `authenticated_agent_transport_proven`;
- `full_bridge_command_flow_proven`;
- `bootstrap_retired`;
- `pairing_ready`.

No PR promotion or merge is authorized by this checkpoint.

## Added authority

- `src/hms_gpt_vps/agent_bridge_tls_storage.py`
- `src/hms_gpt_vps/agent_bridge_production_tls.py`
- `tests/test_r002f_agent_bridge_tls_storage.py`
- `tests/test_r002f_agent_bridge_production_tls.py`

Pre-publication scratch validation:

- Python syntax compilation: PASS.
- Focused candidate tests: 24/24 PASS using dependency stubs.
- This is not a substitute for the repository test suite, GitHub Actions, or real Windows/Hyper-V execution.
