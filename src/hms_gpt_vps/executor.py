from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence

from .audit import AuditLog
from .policy import Decision, PolicyRequest, evaluate
from .workspace import Workspace


class ExecutionDenied(PermissionError):
    pass


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def run_command(
    workspace: Workspace,
    argv: Sequence[str],
    *,
    capability: str,
    audit_log: AuditLog,
    timeout_seconds: float = 60.0,
    destructive: bool = False,
    explicitly_approved: bool = False,
) -> CommandResult:
    if not argv or not argv[0].strip():
        raise ValueError("argv must contain an executable")

    decision = evaluate(
        PolicyRequest(
            capability=capability,
            project_id=workspace.project_id,
            destructive=destructive,
            explicitly_approved=explicitly_approved,
        )
    )
    if decision is not Decision.ALLOW:
        audit_log.append(
            action=capability,
            project_id=workspace.project_id,
            outcome=decision.value,
            argv=list(argv),
        )
        raise ExecutionDenied(f"execution blocked by policy: {decision.value}")

    try:
        completed = subprocess.run(
            list(argv),
            cwd=workspace.root,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        audit_log.append(
            action=capability,
            project_id=workspace.project_id,
            outcome="error",
            argv=list(argv),
            error=type(exc).__name__,
        )
        raise

    audit_log.append(
        action=capability,
        project_id=workspace.project_id,
        outcome="ok" if completed.returncode == 0 else "failed",
        argv=list(argv),
        returncode=completed.returncode,
    )
    return CommandResult(
        argv=tuple(argv),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
