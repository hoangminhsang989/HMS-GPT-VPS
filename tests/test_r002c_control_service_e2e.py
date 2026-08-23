from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from hms_gpt_vps.audit import AuditLog
from hms_gpt_vps.control_actions import ControlActionRuntime
from hms_gpt_vps.control_gateway import ControlGateway
from hms_gpt_vps.control_request import CONTROL_REQUEST_SCHEMA_VERSION, ControlRequest
from hms_gpt_vps.control_service import (
    LocalApprovalError,
    ControlService,
    approve_control_request_locally,
)
from hms_gpt_vps.control_session import issue_control_session
from hms_gpt_vps.control_session_store import ControlSessionStore
from hms_gpt_vps.executor import ExecutionDenied
from hms_gpt_vps.idempotency_store import IdempotencyInProgressError, IdempotencyStore
from hms_gpt_vps.pairing import consume_pairing_record, issue_pairing_grant
from hms_gpt_vps.workspace import Workspace


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)
INSTANCE_ID = "hms-01"


def build_service(tmp_path):
    pair = issue_pairing_grant(
        INSTANCE_ID,
        "https://bridge.example.test",
        scopes=("workspace.read", "workspace.write"),
        now=NOW,
    )
    consumed = consume_pairing_record(
        pair.record,
        pair.token,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )
    session = issue_control_session(
        consumed,
        scopes=("workspace.read", "workspace.write"),
        now=NOW + timedelta(seconds=2),
        ttl_seconds=3600,
    )

    session_store = ControlSessionStore(tmp_path / "session.sqlite3")
    session_store.create(session)
    idempotency_store = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    audit = AuditLog(tmp_path / "audit.jsonl")
    gateway = ControlGateway(session_store, idempotency_store, audit_log=audit)

    root = tmp_path / "workspace"
    root.mkdir()
    runtime = ControlActionRuntime(
        instance_id=INSTANCE_ID,
        workspace=Workspace(project_id="project-01", root=root),
        audit_log=audit,
    )
    service = ControlService(gateway, runtime)
    return service, session, session_store, idempotency_store, audit


def make_request(session_id: str, request_id: str, action: str, params: dict) -> ControlRequest:
    return ControlRequest(
        schema_version=CONTROL_REQUEST_SCHEMA_VERSION,
        request_id=request_id,
        instance_id=INSTANCE_ID,
        session_id=session_id,
        action=action,
        params=params,
    )


def test_authenticated_create_replay_and_read_proof(tmp_path) -> None:
    service, session, _session_store, _idem_store, audit = build_service(tmp_path)
    create = make_request(
        session.record.session_id,
        "create-01",
        "workspace.write",
        {
            "path": "chatgpt-control-test.txt",
            "content": "HMS control proof",
            "mode": "create",
        },
    )

    first = service.handle(create, session.token, now=NOW + timedelta(seconds=3))
    replay = service.handle(create, session.token, now=NOW + timedelta(seconds=4))
    assert replay == first
    assert first["sha256"] == hashlib.sha256(b"HMS control proof").hexdigest()

    read = make_request(
        session.record.session_id,
        "read-01",
        "workspace.read",
        {"path": "chatgpt-control-test.txt"},
    )
    read_back = service.handle(read, session.token, now=NOW + timedelta(seconds=5))
    assert read_back["content"] == "HMS control proof"
    assert read_back["sha256"] == first["sha256"]
    assert read_back["size"] == len(b"HMS control proof")

    raw_audit = audit.path.read_text(encoding="utf-8")
    assert session.token not in raw_audit
    assert "HMS control proof" not in raw_audit


def test_remote_request_cannot_self_approve_replace(tmp_path) -> None:
    service, session, _session_store, _idem_store, _audit = build_service(tmp_path)
    create = make_request(
        session.record.session_id,
        "create-01",
        "workspace.write",
        {"path": "replace.txt", "content": "before", "mode": "create"},
    )
    created = service.handle(create, session.token, now=NOW + timedelta(seconds=3))

    replace = make_request(
        session.record.session_id,
        "replace-denied-01",
        "workspace.write",
        {
            "path": "replace.txt",
            "content": "after",
            "mode": "replace",
            "expected_sha256": created["sha256"],
            "explicitly_approved": True,
        },
    )
    with pytest.raises(ExecutionDenied, match="require_approval"):
        service.handle(replace, session.token, now=NOW + timedelta(seconds=4))

    approval = approve_control_request_locally(replace, now=NOW + timedelta(seconds=5))
    with pytest.raises(IdempotencyInProgressError, match="automatic replay is blocked"):
        service.handle(
            replace,
            session.token,
            local_approval=approval,
            now=NOW + timedelta(seconds=5),
        )

    assert service.runtime.workspace.resolve("replace.txt").read_text(encoding="utf-8") == "before"


def test_local_approval_is_bound_to_exact_request_hash(tmp_path) -> None:
    service, session, _session_store, _idem_store, _audit = build_service(tmp_path)
    create = make_request(
        session.record.session_id,
        "create-01",
        "workspace.write",
        {"path": "replace.txt", "content": "before", "mode": "create"},
    )
    created = service.handle(create, session.token, now=NOW + timedelta(seconds=3))

    approved_request = make_request(
        session.record.session_id,
        "replace-ok-01",
        "workspace.write",
        {
            "path": "replace.txt",
            "content": "after",
            "mode": "replace",
            "expected_sha256": created["sha256"],
        },
    )
    approval = approve_control_request_locally(
        approved_request,
        now=NOW + timedelta(seconds=4),
    )

    changed_request = make_request(
        session.record.session_id,
        "replace-ok-01",
        "workspace.write",
        {
            "path": "replace.txt",
            "content": "tampered",
            "mode": "replace",
            "expected_sha256": created["sha256"],
        },
    )
    with pytest.raises(LocalApprovalError, match="request hash mismatch"):
        service.handle(
            changed_request,
            session.token,
            local_approval=approval,
            now=NOW + timedelta(seconds=4),
        )

    assert service.runtime.workspace.resolve("replace.txt").read_text(encoding="utf-8") == "before"


def test_fresh_local_approval_allows_exact_replace(tmp_path) -> None:
    service, session, _session_store, _idem_store, _audit = build_service(tmp_path)
    create = make_request(
        session.record.session_id,
        "create-01",
        "workspace.write",
        {"path": "replace.txt", "content": "before", "mode": "create"},
    )
    created = service.handle(create, session.token, now=NOW + timedelta(seconds=3))

    replace = make_request(
        session.record.session_id,
        "replace-ok-01",
        "workspace.write",
        {
            "path": "replace.txt",
            "content": "after",
            "mode": "replace",
            "expected_sha256": created["sha256"],
        },
    )
    approval = approve_control_request_locally(replace, now=NOW + timedelta(seconds=4))
    result = service.handle(
        replace,
        session.token,
        local_approval=approval,
        now=NOW + timedelta(seconds=4),
    )

    assert result["sha256"] == hashlib.sha256(b"after").hexdigest()
    assert service.runtime.workspace.resolve("replace.txt").read_text(encoding="utf-8") == "after"


def test_expired_local_approval_fails_closed_and_leaves_claim_ambiguous(tmp_path) -> None:
    service, session, _session_store, _idem_store, _audit = build_service(tmp_path)
    create = make_request(
        session.record.session_id,
        "create-01",
        "workspace.write",
        {"path": "replace.txt", "content": "before", "mode": "create"},
    )
    created = service.handle(create, session.token, now=NOW + timedelta(seconds=3))

    replace = make_request(
        session.record.session_id,
        "replace-expired-01",
        "workspace.write",
        {
            "path": "replace.txt",
            "content": "after",
            "mode": "replace",
            "expected_sha256": created["sha256"],
        },
    )
    approval = approve_control_request_locally(replace, now=NOW)
    with pytest.raises(LocalApprovalError, match="expired"):
        service.handle(
            replace,
            session.token,
            local_approval=approval,
            now=NOW + timedelta(seconds=301),
        )

    assert service.runtime.workspace.resolve("replace.txt").read_text(encoding="utf-8") == "before"
