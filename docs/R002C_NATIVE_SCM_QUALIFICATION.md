# R002C native packaged Agent SCM qualification

This gate runs the attested `hms-agent/` onedir package, whose entrypoint is `hms-agent.exe`, as a real Windows service on an ephemeral GitHub-hosted Windows runner.

It is intentionally stricter than a unit/integration test but narrower than the final managed Hyper-V guest qualification.

## Positive proofs

The qualification harness fails closed unless all of these are proven with the attested package tree:

- runner is Windows and the qualification process has Administrator rights;
- no pre-existing `HMSAgent` service or HMS managed qualification roots exist;
- package-manifest v2, exact package file set, aggregate size, per-file SHA-256 values and the Windows AMD64 PE entrypoint are valid before install;
- a fresh machine-scope DPAPI device credential is created in the managed State directory;
- the production service-install script creates `HMSAgent` as `NT AUTHORITY\LocalService`, enables an unrestricted per-service SID `NT SERVICE\HMSAgent` and applies the production ACL contract;
- the packaged service reaches SCM `Running`, which requires its internal native token proof, protected config load and LocalMachine-DPAPI credential load to have completed;
- the production service-readiness contract passes, including exact package-tree/config checks and the service-SID ACL checks;
- the packaged process publishes valid `/healthz` evidence reporting the per-service identity `NT SERVICE\HMSAgent`, `non-admin`, the exact instance/workspace/version and canonical capability set;
- external `Get-NetTCPConnection` evidence proves exactly one health listener owned by the service process and bound to `127.0.0.1` only;
- the outbound runtime creates a durable connection epoch and increments it while retrying a deliberately closed loopback HTTPS target;
- a graceful SCM stop removes the health listener;
- SCM restart succeeds, produces a new `boot_id`, reloads the machine DPAPI credential and advances the durable connection epoch monotonically;
- the complete package tree is reverified before proof completion;
- the service and qualification-owned filesystem roots are removed after the proof.

The proof artifact is non-secret. The random device secret is never written to the proof or logs and the DPAPI credential is removed during cleanup.

## Deliberate limits

The retry target is a closed loopback HTTPS port. Therefore this gate does **not** claim a successful Bridge session or remote command flow. It also runs on the CI Windows host, not inside the managed Hyper-V guest. Both facts are explicit in the proof artifact and remain separate final qualification requirements.
