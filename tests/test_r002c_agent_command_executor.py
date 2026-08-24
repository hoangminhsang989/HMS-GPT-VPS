from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

from hms_gpt_vps.agent_command_executor import AgentPolicyCommandExecutor
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
)
from hms_gpt_vps.audit import AuditLog
from hms_gpt_vps.control_actions import ControlActionRuntime
from hms_gpt_vps.workspace import Workspace


def _command(
    *,
    request_id: str,
    instance_id: str,
    action: str,
    params: dict[str, object],
    approved: bool = False,
) -> AgentCommandEnvelope:
    deadline = datetime.now(timezone.utc) + timedelta(minutes=5)
    unsigned = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id=request_id,
        instance_id=instance_id,
        action=action,
        params=params,
        deadline_at=deadline,
    )
    if not approved:
        return unsigned
    return AgentCommandEnvelope(
        schema_version=unsigned.schema_version,
        request_id=unsigned.request_id,
        instance_id=unsigned.instance_id,
        action=unsigned.action,
        params=unsigned.params,
        deadline_at=unsigned.deadline_at,
        approved_command_sha256=unsigned.command_sha256(),
    )


def _executor(tmp_path):
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    runtime = ControlActionRuntime(
        instance_id="instance-1",
        workspace=Workspace(project_id="project-1", root=workspace_root),
        audit_log=AuditLog(tmp_path / "audit.jsonl"),
    )
    return AgentPolicyCommandExecutor(runtime), workspace_root


def test_agent_executor_reuses_workspace_runtime_for_create_and_read(tmp_path) -> None:
    executor, workspace_root = _executor(tmp_path)

    created = executor(
        _command(
            request_id="req-create",
            instance_id="instance-1",
            action="workspace.write",
            params={"path": "proof.txt", "content": "hello", "mode": "create"},
        )
    )
    assert created.outcome == "ok"
    assert (workspace_root / "proof.txt").read_text(encoding="utf-8") == "hello"

    read = executor(
        _command(
            request_id="req-read",
            instance_id="instance-1",
            action="workspace.read",
            params={"path": "proof.txt"},
        )
    )
    assert read.outcome == "ok"
    assert read.response["content"] == "hello"
    assert read.response["sha256"] == hashlib.sha256(b"hello").hexdigest()


def test_agent_executor_requires_signed_exact_approval_for_replace(tmp_path) -> None:
    executor, workspace_root = _executor(tmp_path)
    target = workspace_root / "proof.txt"
    target.write_text("old", encoding="utf-8")
    old_sha256 = hashlib.sha256(b"old").hexdigest()

    denied = executor(
        _command(
            request_id="req-replace-denied",
            instance_id="instance-1",
            action="workspace.write",
            params={
                "path": "proof.txt",
                "content": "new",
                "mode": "replace",
                "expected_sha256": old_sha256,
            },
        )
    )
    assert denied.outcome == "denied"
    assert target.read_text(encoding="utf-8") == "old"

    approved = executor(
        _command(
            request_id="req-replace-approved",
            instance_id="instance-1",
            action="workspace.write",
            params={
                "path": "proof.txt",
                "content": "new",
                "mode": "replace",
                "expected_sha256": old_sha256,
            },
            approved=True,
        )
    )
    assert approved.outcome == "ok"
    assert target.read_text(encoding="utf-8") == "new"


def test_agent_executor_fails_closed_on_wrong_instance_and_precondition(tmp_path) -> None:
    executor, workspace_root = _executor(tmp_path)

    wrong_instance = executor(
        _command(
            request_id="req-wrong-instance",
            instance_id="instance-2",
            action="workspace.read",
            params={"path": "missing.txt"},
        )
    )
    assert wrong_instance.outcome == "denied"

    missing = executor(
        _command(
            request_id="req-missing",
            instance_id="instance-1",
            action="workspace.read",
            params={"path": "missing.txt"},
        )
    )
    assert missing.outcome == "failed"
    assert not (workspace_root / "missing.txt").exists()
