# R002F reviewed execution preflight remediation

Status: `STAGED_NOT_EXECUTED`

This descendant remediates the independent committed-byte review rejection of
`02324b36e9a2110aa90831cb785918231f82fb6b`.

Rejected findings:

1. the component preflight learned `runner_source_commit` from the checkout being
   qualified and then compared the checkout to that self-reported value;
2. Git checkout validation inherited caller-controlled `GIT_*` authority
   variables, so `git -C <repo>` could observe a repository/index authority other
   than the lexical source path recorded in qualification evidence.

## Reviewed runner commit authority

Production preflight now has a separate reviewed wrapper. It requires:

`--expected-runner-source-commit <40-hex-reviewed-commit>`

The expected commit is an external authority. It is never derived from `HEAD`.
Before and after the component preflight, the wrapper requires the checkout to
match that exact commit.

The final proof uses qualification:

`R002F_REVIEWED_EXECUTION_PREFLIGHT`

Only this final proof may authorize one-shot execution.

The earlier `R002F_ZERO_MANUAL_EXECUTION_PREFLIGHT` result is retained only as a
component proof. Its SHA-256 is bound into the final proof and the final proof
sets:

`component_preflight_authority=false`

## Git authority hardening

Checkout validation constructs a child environment that removes caller-supplied
Git-control variables case-insensitively. This includes `GIT_DIR`,
`GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR`, Git config/object redirect
variables, and every other caller-provided `GIT_*` name.

After removal it sets only:

`GIT_NO_REPLACE_OBJECTS=1`

for Git authority reads.

Bootstrap username/password are additionally removed from Git validation child
environments.

The reviewed gate also requires:

- lexical repo root is not a link/reparse traversal;
- `git rev-parse --show-toplevel` equals the lexical repo authority;
- `HEAD` equals the externally reviewed commit;
- status contains no modified, untracked, or ignored content;
- `git ls-files -v` reports normal `H` authority for every tracked entry, rejecting
  skip-worktree/assume-unchanged or other non-normal index flags;
- fsmonitor and untracked-cache acceleration are disabled for the check.

## One-shot execution command

The live runner script now requires both:

- `--runner-source-commit`
- `--reviewed-runner-source-commit`

and requires exact equality.

The old component preflight does not emit the reviewed flag, so its raw command
is intentionally no longer executable. The reviewed wrapper inserts the flag
only after both reviewed checkout gates pass and the component result reports the
same runner commit.

Before invoking the one-shot coordinator, the live runner sanitizes Git-control
environment and performs the reviewed clean-checkout gate again. The sanitized
environment is then passed into the coordinator, so its repeated checkout checks
cannot inherit the caller's Git redirect variables.

## Bootstrap credential boundary

The reviewed preflight still runs before bootstrap username/password are set.
Git validation never receives their values. If the component preflight observes
bootstrap credentials already present in the actual process environment, its
existing fail-closed blocker remains authoritative in the component status.

The previous documentation statement that the secret-environment condition
always determines the top-level status was too strong: the component manifest
uses missing-authority precedence when other non-secret authority is absent.
The exact `host_blockers` list remains the factual evidence.

## Proof boundary

This remediation is code/test/document authority only.

It does not prove:

- a Windows production-host execution;
- Hyper-V guest qualification;
- HMSBridge live activation;
- OpenAI tunnel activation;
- ChatGPT OAuth/UI provenance;
- bootstrap retirement;
- pairing readiness;
- full Bridge command flow.

No Windows/live execution is authorized until this descendant receives a fresh
independent committed-byte review and the reviewed preflight is then executed on
the production qualification host.
