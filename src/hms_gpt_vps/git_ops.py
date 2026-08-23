from __future__ import annotations

from .audit import AuditLog
from .executor import CommandResult, run_command
from .workspace import Workspace


def status(workspace: Workspace, audit_log: AuditLog) -> CommandResult:
    return run_command(
        workspace,
        ["git", "status", "--short", "--branch"],
        capability="git.status",
        audit_log=audit_log,
    )


def diff(workspace: Workspace, audit_log: AuditLog) -> CommandResult:
    return run_command(
        workspace,
        ["git", "diff", "--check"],
        capability="git.diff",
        audit_log=audit_log,
    )


def log(workspace: Workspace, audit_log: AuditLog, limit: int = 10) -> CommandResult:
    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")
    return run_command(
        workspace,
        ["git", "log", f"-{limit}", "--oneline", "--decorate"],
        capability="git.log",
        audit_log=audit_log,
    )
