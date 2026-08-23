# HMS-GPT-VPS

HMS-GPT-VPS is the GitHub authority for the HMS VPS Agent project: a controlled bridge that allows ChatGPT/HMS tooling to operate an authorized VPS for development, testing, deployment, monitoring, and project automation.

## Core principles

- Repository-first development: source and working artifacts live in GitHub, not ChatGPT file storage.
- Fail-closed security: deny by default when authorization, scope, or policy is ambiguous.
- Least privilege: the agent should not run as root by default.
- Project isolation: commands and file access are restricted to explicitly authorized project roots.
- Destructive actions require explicit approval.
- Every privileged action must be auditable.

## Initial architecture

`ChatGPT / HMS Bridge -> authenticated transport -> HMS VPS Agent -> policy engine -> shell/files/git/services/telemetry`

## Current stage

Stage 0 — Foundation/bootstrap.

See `PROJECT_STATE.md` and the documents under `docs/` for the current authority and roadmap.
