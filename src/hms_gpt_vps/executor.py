from __future__ import annotations

from pathlib import Path
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


def _require_trusted_executable(raw: str) -> str:
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ExecutionDenied("trusted executable must be an absolute path")
    if candidate.is_symlink():
        raise ExecutionDenied("trusted executable must not be a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ExecutionDenied("trusted executable does not exist") from exc
    if not resolved.is_file():
        raise ExecutionDenied("trusted executable is not a regular file")
    return str(resolved)


def run_command(
    workspace: Workspace,
    argv: Sequence[str],
    *,
    capability: str,
    audit_log: AuditLog,
    timeout_seconds: float = 60.0,
    destructive: bool = False,
    explicitly_approved: bool = False,
    require_trusted_executable: bool = False,
) -> CommandResult:
    if not argv or not isinstance(argv[0], str) or not argv[0].strip():
        raise ValueError("argv must contain an executable")

    argv_list = list(argv)
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
            argv=argv_list,
        )
        raise ExecutionDenied(f"execution blocked by policy: {decision.value}")

    if require_trusted_executable:
        try:
            argv_list[0] = _require_trusted_executable(argv_list[0])
        except ExecutionDenied:
            audit_log.append(
                action=capability,
                project_id=workspace.project_id,
                outcome="deny",
                argv=argv_list,
                error="untrusted_executable",
            )
            raise

    try:
        completed = subprocess.run(
            argv_list,
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
            argv=argv_list,
            error=type(exc).__name__,
        )
        raise

    audit_log.append(
        action=capability,
        project_id=workspace.project_id,
        outcome="ok" if completed.returncode == 0 else "failed",
        argv=argv_list,
        returncode=completed.returncode,
    )
    return CommandResult(
        argv=tuple(argv_list),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
