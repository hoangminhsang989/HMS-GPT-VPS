# R002F isolated Python + pinned Git toolchain authority remediation

Status: `STAGED_NOT_EXECUTED`

This descendant remediates the fresh committed-byte review rejection of
`17105c84f62237b547eb98bc3f241088f8cc6ff8`.

Rejected findings:

1. reviewed checkout commands still resolved literal `git` through caller-controlled
   `PATH`;
2. the reviewed preflight and live one-shot entrypoints imported `hms_gpt_vps`
   before requiring an isolated Python import boundary.

## External Git executable authority

Reviewed production preflight now requires both:

- `--git-executable <absolute-path>`
- `--git-executable-sha256 <64-lowercase-hex>`

The executable is never discovered with `PATH`.

The reviewed checkout gate:

- rejects symlink/junction/reparse traversal;
- requires an existing regular executable file;
- checks the exact external SHA-256 authority;
- on Windows opens the executable with `CreateFileW` and `FILE_SHARE_READ` only;
- keeps that handle open during all checkout evidence commands, denying write/delete
  sharing while the command set executes;
- executes the absolute pinned path as argv[0];
- rechecks path identity before and after each Git command;
- strips caller-provided `GIT_*` environment variables case-insensitively;
- removes bootstrap credential variables from checkout validation children;
- disables replacement objects, fsmonitor, and untracked-cache acceleration;
- requires exact top-level path, exact reviewed HEAD, empty modified/untracked/ignored
  status, and normal `H` index flags only.

On non-Windows hosts the module provides a regular-file pinned descriptor for
tests/development; production qualification remains Windows-only.

## Isolated Python entrypoint authority

Both production-facing entrypoints now fail before any `hms_gpt_vps` import unless
`sys.flags.isolated == 1`.

They must therefore be launched with:

`python -I ...`

Before project import they use only Python standard-library code to:

- parse the exact `--repo-root`;
- reject symlink/reparse traversal for repo, `src`, and `scripts`;
- require `src` and `scripts` to be direct children of the repo root;
- insert exactly `<repo>\src` at the front of `sys.path`.

Hostile `PYTHONPATH` and user-site import paths therefore do not supply project
modules.

The reviewed preflight-generated live command is rewritten to:

- use the exact current `sys.executable`;
- include `-I -X utf8`;
- call the exact reviewed repo one-shot script;
- bind the reviewed runner commit;
- bind the explicit Git executable path and SHA-256.

The old path-controlled Python argv emitted by the component preflight is not
published as the reviewed live command.

## Live coordinator checkout revalidation

The one-shot CLI passes a reviewed checkout-validator closure into
`run_r002f_one_shot_production_qualification()`.

Therefore every coordinator checkout recheck uses the same:

- external reviewed commit;
- absolute Git executable;
- Git executable SHA-256;
- sanitized Git-control environment.

The coordinator never falls back to literal PATH-resolved `git` for an authorized
reviewed run.

## Regression requirements

The focused regression covers:

- hostile `PATH` with a fake Git candidate: command argv[0] remains the exact pinned
  executable path;
- external Git digest mismatch;
- `GIT_DIR`/other Git-control environment removal;
- exact reviewed HEAD mismatch;
- skip-worktree/non-normal index flag rejection;
- reviewed one-shot argv contains `-I` and exact Git authority;
- non-isolated entrypoints fail before project import;
- isolated entrypoints ignore hostile `PYTHONPATH`.

## Operational invocation

The reviewed preflight must be invoked in isolated mode and with an independently
approved Git binary authority, for example:

```powershell
& 'C:\Path\To\python.exe' -I `
  'C:\Path\To\HMS-GPT-VPS\scripts\preflight_r002f_reviewed_one_shot_production_qualification.py' `
  --repo-root 'C:\Path\To\HMS-GPT-VPS' `
  --proof 'D:\HMS-Proofs\r002f-reviewed-preflight.json' `
  --expected-runner-source-commit '<reviewed-40-hex-commit>' `
  --git-executable 'C:\Program Files\Git\cmd\git.exe' `
  --git-executable-sha256 '<independently-approved-64-hex-sha256>' `
  <remaining non-secret authority arguments>
```

The Git SHA-256 must come from deployment/review authority. The code must not
self-promote an observed Git path/hash into approved authority.

## Proof boundary

This remediation remains `STAGED_NOT_EXECUTED`.

It does not prove:

- production Windows execution;
- Hyper-V guest qualification;
- HMSBridge activation;
- OpenAI tunnel activation;
- ChatGPT OAuth/UI provenance;
- bootstrap retirement;
- pairing readiness;
- full Bridge command flow.

A fresh independent committed-byte review of the descendant is required before
Windows execution is authorized.
