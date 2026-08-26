# R002F one-shot production qualification coordinator

Status: `STAGED_NOT_EXECUTED`

This tranche turns the existing independent R002E/R002F qualification runners into one bounded Windows execution sequence. It does not weaken any individual gate and it does not claim that the sequence has already executed.

The coordinator runs, in order:

1. strict managed Hyper-V Agent qualification;
2. HMSBridge composite activation;
3. authenticated Agent transport with the reviewed secure MCP tunnel;
4. OpenAI control-plane protected MCP read; and
5. the existing R002F production cross-proof gate.

A final `06-one-shot-manifest.json` is created only when every component runner exits successfully, every component proof is present and readable through the pinned-file authority, the source checkout remains clean at the exact reviewed commit, and the cross-proof identity gate closes.

## Source checkout authority

The coordinator requires:

- an explicit `runner_source_commit`;
- `git rev-parse HEAD` to equal that exact commit;
- a clean tracked and untracked worktree before every live child step and again before final publication;
- the run directory to be outside the source checkout; and
- every child Python process to run in isolated mode (`-I`) with the checkout's exact `src` directory inserted explicitly by a fixed bootstrap; and
- Python interpreter injection variables such as `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONINSPECT`, `PYTHONWARNINGS`, `PYTHONBREAKPOINT`, `PYTHONUSERBASE`, and `PYTHONSAFEPATH` removed from child environments.

This prevents a successful proof bundle from silently referring to a different or dirty runner checkout.

`challenge_source_commit` is separate from `runner_source_commit`. The former is the source authority for the protected workspace read challenged through MCP; the latter identifies the exact qualification code that orchestrates the run.

## Secret boundary

The existing bootstrap credential environment variables are required for live Windows/guest qualification, but:

- their values are never placed on a command line;
- they are never included in proof JSON;
- each child receives an independent environment copy;
- Git authority checks are executed with the bootstrap variables removed; and
- the final cross-proof gate needs no bootstrap secret.

A child runner may remove its credential variables from its own process environment without affecting later children.

## Failure behavior

The run directory must not exist before start. It is created once under a non-redirected existing parent.

The coordinator never deletes a partial run. If any step fails, later live steps are not started and the final one-shot manifest is not published. A secret-free `qualification-failure.json` diagnostic may be written with only:

- runner source commit;
- failed step;
- exception type; and
- child exit code when available.

Partial artifacts are retained for forensic review. They are not promoted to a production proof bundle.

## Successful bundle

The run directory names are fixed:

- `01-managed-hyperv.json`
- `02-composite-activation.json`
- `03-authenticated-agent-transport.json`
- `04-openai-control-plane-challenge.json`
- `04-openai-control-plane.json`
- `05-cross-proof.json`
- `06-one-shot-manifest.json`

The final manifest binds SHA-256 for every component proof, the published OpenAI challenge artifact, and the cross-proof artifact. It may state the already-executed component live proofs and their identity binding as true.

It must continue to keep these independent proof boundaries false:

- `chatgpt_ui_origin_proven`
- `token_specific_client_auth_attestation_proven`
- `token_endpoint_private_key_jwt_exchange_proven`
- `chatgpt_app_oauth_client_proven`
- `full_bridge_command_flow_proven`
- `bootstrap_retired`
- `pairing_ready`
- `automatic_start_enabled`

Therefore a successful one-shot run still does not prove a specific ChatGPT UI/user gesture, ChatGPT-specific token issuance provenance, bootstrap retirement, or the final full ChatGPT-to-Agent command path.

## Execution prerequisites

The one-shot coordinator is intended for the real authorized Windows host after the existing product/runtime prerequisites are present:

- Administrator authority;
- an existing managed Hyper-V guest at the supported late-Agent checkpoint;
- exact package/runtime/registry/provisioning/device-credential authorities;
- installed/provisioned HMSBridge and reviewed secure tunnel;
- managed guest trust-root certificate;
- valid bootstrap credential environment variables;
- an externally observed OpenAI control-plane MCP challenge; and
- a new proof run directory outside the source checkout.

At this commit checkpoint, repository-wide pytest, GitHub CI, Windows Administrator execution, Hyper-V execution, live tunnel execution, ChatGPT OAuth, and the full ChatGPT-to-Agent flow remain unexecuted project proof.
