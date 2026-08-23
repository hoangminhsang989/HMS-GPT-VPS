from pathlib import Path

import pytest

from hms_gpt_vps.audit import AuditLog
from hms_gpt_vps.executor import ExecutionDenied, run_command
from hms_gpt_vps.workspace import Workspace


def test_destructive_execution_requires_approval(tmp_path: Path) -> None:
    workspace = Workspace(project_id="p1", root=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")

    with pytest.raises(ExecutionDenied):
        run_command(
            workspace,
            ["python", "-c", "print('blocked')"],
            capability="test.command",
            audit_log=audit,
            destructive=True,
        )


def test_non_destructive_command_runs(tmp_path: Path) -> None:
    workspace = Workspace(project_id="p1", root=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    result = run_command(
        workspace,
        ["python", "-c", "print('ok')"],
        capability="test.command",
        audit_log=audit,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "ok"
