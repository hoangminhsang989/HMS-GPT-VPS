from pathlib import Path
import sys

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


def test_trusted_execution_rejects_relative_executable(tmp_path: Path) -> None:
    workspace = Workspace(project_id="p1", root=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")

    with pytest.raises(ExecutionDenied, match="absolute path"):
        run_command(
            workspace,
            ["python", "-c", "print('blocked')"],
            capability="test.command",
            audit_log=audit,
            require_trusted_executable=True,
        )

    assert "untrusted_executable" in audit.path.read_text(encoding="utf-8")


def test_trusted_execution_runs_canonical_absolute_executable(tmp_path: Path) -> None:
    workspace = Workspace(project_id="p1", root=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    executable = str(Path(sys.executable).resolve(strict=True))

    result = run_command(
        workspace,
        [executable, "-c", "print('trusted-ok')"],
        capability="test.command",
        audit_log=audit,
        require_trusted_executable=True,
    )

    assert result.returncode == 0
    assert result.argv[0] == executable
    assert result.stdout.strip() == "trusted-ok"


def test_trusted_execution_rejects_missing_absolute_executable(tmp_path: Path) -> None:
    workspace = Workspace(project_id="p1", root=tmp_path)
    audit = AuditLog(tmp_path / "audit.jsonl")
    missing = str((tmp_path.parent / "missing-tool.exe").resolve())

    with pytest.raises(ExecutionDenied, match="does not exist"):
        run_command(
            workspace,
            [missing, "--version"],
            capability="test.command",
            audit_log=audit,
            require_trusted_executable=True,
        )
