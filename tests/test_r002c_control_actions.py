from __future__ import annotations

import hashlib
import json

import pytest

from hms_gpt_vps.audit import AuditLog
from hms_gpt_vps.control_actions import (
    MAX_COMMAND_OUTPUT_BYTES,
    ControlActionPreconditionError,
    ControlActionRuntime,
)
from hms_gpt_vps.control_request import CONTROL_REQUEST_SCHEMA_VERSION, ControlRequest
from hms_gpt_vps.executor import CommandResult, ExecutionDenied
from hms_gpt_vps.workspace import Workspace, WorkspaceViolation


INSTANCE_ID = "hms-01"
SESSION_ID = "session-01"


def make_runtime(tmp_path) -> ControlActionRuntime:
    root = tmp_path / "workspace"
    root.mkdir()
    return ControlActionRuntime(
        instance_id=INSTANCE_ID,
        workspace=Workspace(project_id="project-01", root=root),
        audit_log=AuditLog(tmp_path / "audit.jsonl"),
        python_executable="python-test",
    )


def request(action: str, params: dict, *, request_id: str = "request-01") -> ControlRequest:
    return ControlRequest(
        schema_version=CONTROL_REQUEST_SCHEMA_VERSION,
        request_id=request_id,
        instance_id=INSTANCE_ID,
        session_id=SESSION_ID,
        action=action,
        params=params,
    )


def test_workspace_create_then_read_round_trip(tmp_path) -> None:
    runtime = make_runtime(tmp_path)
    created = runtime.execute(
        request(
            "workspace.write",
            {"path": "nested/control.txt", "content": "hello", "mode": "create"},
        )
    )
    assert created["ok"] is True
    assert created["sha256"] == hashlib.sha256(b"hello").hexdigest()

    read_back = runtime.execute(
        request("workspace.read", {"path": "nested/control.txt"}, request_id="request-02")
    )
    assert read_back["content"] == "hello"
    assert read_back["encoding"] == "utf-8"
    assert read_back["sha256"] == created["sha256"]


def test_workspace_create_refuses_existing_file(tmp_path) -> None:
    runtime = make_runtime(tmp_path)
    target = runtime.workspace.resolve("existing.txt")
    target.write_text("original", encoding="utf-8")

    with pytest.raises(ControlActionPreconditionError, match="refuses to overwrite"):
        runtime.execute(
            request(
                "workspace.write",
                {"path": "existing.txt", "content": "new", "mode": "create"},
            )
        )
    assert target.read_text(encoding="utf-8") == "original"


def test_workspace_replace_requires_trusted_approval_and_sha_precondition(tmp_path) -> None:
    runtime = make_runtime(tmp_path)
    target = runtime.workspace.resolve("replace.txt")
    target.write_text("before", encoding="utf-8")
    before_sha = hashlib.sha256(b"before").hexdigest()
    replace = request(
        "workspace.write",
        {
            "path": "replace.txt",
            "content": "after",
            "mode": "replace",
            "expected_sha256": before_sha,
        },
    )

    with pytest.raises(ExecutionDenied, match="require_approval"):
        runtime.execute(replace)
    assert target.read_text(encoding="utf-8") == "before"

    result = runtime.execute(replace, explicitly_approved=True)
    assert target.read_text(encoding="utf-8") == "after"
    assert result["sha256"] == hashlib.sha256(b"after").hexdigest()


def test_workspace_replace_rejects_stale_sha_even_when_approved(tmp_path) -> None:
    runtime = make_runtime(tmp_path)
    target = runtime.workspace.resolve("replace.txt")
    target.write_text("current", encoding="utf-8")

    with pytest.raises(ControlActionPreconditionError, match="does not match"):
        runtime.execute(
            request(
                "workspace.write",
                {
                    "path": "replace.txt",
                    "content": "after",
                    "mode": "replace",
                    "expected_sha256": hashlib.sha256(b"stale").hexdigest(),
                },
            ),
            explicitly_approved=True,
        )
    assert target.read_text(encoding="utf-8") == "current"


def test_workspace_write_rejects_escape(tmp_path) -> None:
    runtime = make_runtime(tmp_path)
    with pytest.raises(WorkspaceViolation):
        runtime.execute(
            request(
                "workspace.write",
                {"path": "../outside.txt", "content": "blocked", "mode": "create"},
            )
        )
    assert not (tmp_path / "outside.txt").exists()


@pytest.mark.parametrize(
    "path",
    [
        ".git/config",
        ".GiT\\hooks\\pre-commit",
        "sub/.git/index",
        ".git./config",
        ".git:stream",
    ],
)
def test_workspace_write_rejects_git_metadata_paths(tmp_path, path: str) -> None:
    runtime = make_runtime(tmp_path)
    with pytest.raises(ControlActionPreconditionError, match="Git metadata"):
        runtime.execute(
            request(
                "workspace.write",
                {"path": path, "content": "blocked", "mode": "create"},
            )
        )


def test_process_test_uses_fixed_pytest_shape_and_bounds_output(tmp_path, monkeypatch) -> None:
    runtime = make_runtime(tmp_path)
    captured = {}
    oversized = "x" * (MAX_COMMAND_OUTPUT_BYTES + 128)

    def fake_run_command(workspace, argv, **kwargs):
        captured["workspace"] = workspace
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        return CommandResult(
            argv=tuple(argv),
            returncode=0,
            stdout=oversized,
            stderr="warning",
        )

    monkeypatch.setattr("hms_gpt_vps.control_actions.run_command", fake_run_command)
    result = runtime.execute(
        request(
            "process.test",
            {"target": ".", "fail_fast": True, "maxfail": 3, "timeout_seconds": 15},
        )
    )

    assert captured["workspace"] is runtime.workspace
    assert captured["argv"] == [
        "python-test",
        "-m",
        "pytest",
        ".",
        "-q",
        "-x",
        "--maxfail=3",
    ]
    assert captured["kwargs"]["capability"] == "process.test"
    assert captured["kwargs"]["timeout_seconds"] == 15.0
    assert result["stdout_truncated"] is True
    assert result["stdout_bytes"] == len(oversized.encode("utf-8"))
    assert len(result["stdout"].encode("utf-8")) <= MAX_COMMAND_OUTPUT_BYTES
    assert result["stderr_truncated"] is False


def test_process_test_rejects_arbitrary_pytest_arguments(tmp_path) -> None:
    runtime = make_runtime(tmp_path)
    with pytest.raises(ControlActionPreconditionError, match="maxfail"):
        runtime.execute(
            request("process.test", {"target": ".", "maxfail": "1 --collect-only"})
        )


def test_git_status_is_read_only_fixed_command_and_output_is_bounded(tmp_path, monkeypatch) -> None:
    runtime = make_runtime(tmp_path)
    captured = {}

    def fake_run_command(workspace, argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        return CommandResult(
            argv=tuple(argv),
            returncode=0,
            stdout="## main\n",
            stderr="",
        )

    monkeypatch.setattr("hms_gpt_vps.control_actions.run_command", fake_run_command)
    result = runtime.execute(request("git.status", {}))

    assert captured["argv"] == [
        "git",
        "status",
        "--short",
        "--branch",
        "--untracked-files=all",
    ]
    assert captured["kwargs"]["capability"] == "git.status"
    assert result["stdout"] == "## main\n"
    assert result["stdout_truncated"] is False


def test_audit_read_returns_only_requested_tail(tmp_path) -> None:
    runtime = make_runtime(tmp_path)
    runtime.audit_log.append(action="a", project_id="project-01", outcome="ok", marker=1)
    runtime.audit_log.append(action="b", project_id="project-01", outcome="ok", marker=2)
    runtime.audit_log.append(action="c", project_id="project-01", outcome="ok", marker=3)

    result = runtime.execute(request("audit.read", {"limit": 2}))
    assert [event["action"] for event in result["events"]] == ["b", "c"]
    assert [event["detail"]["marker"] for event in result["events"]] == [2, 3]


def test_audit_records_workspace_metadata_not_file_content(tmp_path) -> None:
    runtime = make_runtime(tmp_path)
    secret_marker = "DO-NOT-LOG-CONTENT-12345"
    runtime.execute(
        request(
            "workspace.write",
            {"path": "safe.txt", "content": secret_marker, "mode": "create"},
        )
    )

    raw_audit = runtime.audit_log.path.read_text(encoding="utf-8")
    assert secret_marker not in raw_audit
    event = json.loads(raw_audit.splitlines()[-1])
    assert event["action"] == "workspace.write"
    assert event["detail"]["path"] == "safe.txt"
    assert event["detail"]["sha256"] == hashlib.sha256(secret_marker.encode()).hexdigest()
