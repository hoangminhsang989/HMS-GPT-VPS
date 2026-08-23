from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hms_gpt_vps.audit import AuditLog
from hms_gpt_vps.control_gateway import ControlGateway
from hms_gpt_vps.control_request import (
    CONTROL_REQUEST_SCHEMA_VERSION,
    ControlRequest,
    ControlRequestError,
)
from hms_gpt_vps.control_session import ControlSessionScopeError, issue_control_session
from hms_gpt_vps.control_session_store import ControlSessionStore
from hms_gpt_vps.idempotency_store import (
    IdempotencyConflictError,
    IdempotencyInProgressError,
    IdempotencyStore,
)
from hms_gpt_vps.pairing import consume_pairing_record, issue_pairing_grant


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)


def session(tmp_path: Path, *, scopes: set[str]):
    pairing_grant = issue_pairing_grant(
        "hms-01",
        "https://bridge.example.test",
        scopes=scopes,
        now=NOW,
    )
    consumed = consume_pairing_record(
        pairing_grant.record,
        pairing_grant.token,
        instance_id="hms-01",
        now=NOW + timedelta(seconds=1),
    )
    grant = issue_control_session(consumed, now=NOW + timedelta(seconds=2))
    store = ControlSessionStore(tmp_path / "sessions.sqlite3")
    store.create(grant)
    return grant, store


def request(*, request_id: str = "req-001", action: str = "workspace.read", params=None):
    return ControlRequest(
        schema_version=CONTROL_REQUEST_SCHEMA_VERSION,
        request_id=request_id,
        instance_id="hms-01",
        session_id="placeholder",
        action=action,
        params=params or {"path": "README.md"},
    )


def bind_session(req: ControlRequest, session_id: str) -> ControlRequest:
    return ControlRequest(
        schema_version=req.schema_version,
        request_id=req.request_id,
        instance_id=req.instance_id,
        session_id=session_id,
        action=req.action,
        params=req.params,
    )


def test_request_hash_is_canonical_and_rejects_unknown_action() -> None:
    first = ControlRequest(
        schema_version=1,
        request_id="req-001",
        instance_id="hms-01",
        session_id="session-01",
        action="workspace.read",
        params={"b": 2, "a": 1},
    )
    second = ControlRequest(
        schema_version=1,
        request_id="req-001",
        instance_id="hms-01",
        session_id="session-01",
        action="workspace.read",
        params={"a": 1, "b": 2},
    )
    assert first.request_sha256() == second.request_sha256()

    with pytest.raises(ControlRequestError, match="unsupported control action"):
        ControlRequest(
            schema_version=1,
            request_id="req-001",
            instance_id="hms-01",
            session_id="session-01",
            action="host.admin",
            params={},
        ).validate()


def test_gateway_authorizes_then_replays_completed_result(tmp_path: Path) -> None:
    grant, session_store = session(tmp_path, scopes={"workspace.read"})
    idem = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    gateway = ControlGateway(session_store, idem)
    req = bind_session(request(), grant.record.session_id)

    gate = gateway.begin(req, grant.token, now=NOW + timedelta(seconds=3))
    assert gate.should_execute
    assert gate.replay_response is None

    response = {"ok": True, "sha256": "a" * 64}
    gateway.complete(gate, response, now=NOW + timedelta(seconds=4))

    replay = gateway.begin(req, grant.token, now=NOW + timedelta(seconds=5))
    assert not replay.should_execute
    assert replay.replay_response == response


def test_gateway_denies_missing_scope_before_idempotency_claim(tmp_path: Path) -> None:
    grant, session_store = session(tmp_path, scopes={"workspace.read"})
    idem = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    gateway = ControlGateway(session_store, idem)
    req = bind_session(
        request(action="workspace.write", params={"path": "x.txt", "content": "x"}),
        grant.record.session_id,
    )

    with pytest.raises(ControlSessionScopeError, match="does not grant scope"):
        gateway.begin(req, grant.token, now=NOW + timedelta(seconds=3))

    # If authorization happened after idempotency, this would now be blocked as
    # an unresolved prior claim. Instead, granting a suitable session can use
    # the same request_id safely because no claim was written by the denial.
    write_grant, write_store = session(tmp_path / "write", scopes={"workspace.write"})
    write_gateway = ControlGateway(write_store, idem)
    write_req = ControlRequest(
        schema_version=1,
        request_id=req.request_id,
        instance_id="hms-01",
        session_id=write_grant.record.session_id,
        action=req.action,
        params=req.params,
    )
    assert write_gateway.begin(
        write_req,
        write_grant.token,
        now=NOW + timedelta(seconds=3),
    ).should_execute


def test_unresolved_claim_blocks_automatic_retry(tmp_path: Path) -> None:
    grant, session_store = session(tmp_path, scopes={"workspace.write"})
    gateway = ControlGateway(
        session_store,
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
    )
    req = ControlRequest(
        schema_version=1,
        request_id="req-write-01",
        instance_id="hms-01",
        session_id=grant.record.session_id,
        action="workspace.write",
        params={"path": "x.txt", "content": "hello"},
    )

    first = gateway.begin(req, grant.token, now=NOW + timedelta(seconds=3))
    assert first.should_execute

    with pytest.raises(IdempotencyInProgressError, match="automatic replay is blocked"):
        gateway.begin(req, grant.token, now=NOW + timedelta(seconds=4))


def test_same_idempotency_key_with_changed_request_is_conflict(tmp_path: Path) -> None:
    grant, session_store = session(tmp_path, scopes={"workspace.write"})
    gateway = ControlGateway(
        session_store,
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
    )
    first = ControlRequest(
        schema_version=1,
        request_id="req-write-01",
        instance_id="hms-01",
        session_id=grant.record.session_id,
        action="workspace.write",
        params={"path": "x.txt", "content": "one"},
    )
    changed = ControlRequest(
        schema_version=1,
        request_id="req-write-01",
        instance_id="hms-01",
        session_id=grant.record.session_id,
        action="workspace.write",
        params={"path": "x.txt", "content": "two"},
    )
    gateway.begin(first, grant.token, now=NOW + timedelta(seconds=3))

    with pytest.raises(IdempotencyConflictError, match="different request"):
        gateway.begin(changed, grant.token, now=NOW + timedelta(seconds=4))


def test_gateway_audit_never_contains_token_or_request_params(tmp_path: Path) -> None:
    grant, session_store = session(tmp_path, scopes={"workspace.write"})
    audit_path = tmp_path / "audit.jsonl"
    gateway = ControlGateway(
        session_store,
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        audit_log=AuditLog(audit_path),
    )
    secret_content = "user-file-content-must-not-enter-gateway-audit"
    req = ControlRequest(
        schema_version=1,
        request_id="req-write-01",
        instance_id="hms-01",
        session_id=grant.record.session_id,
        action="workspace.write",
        params={"path": "x.txt", "content": secret_content},
    )

    gate = gateway.begin(req, grant.token, now=NOW + timedelta(seconds=3))
    gateway.complete(gate, {"ok": True}, now=NOW + timedelta(seconds=4))

    audit_text = audit_path.read_text(encoding="utf-8")
    assert grant.token not in audit_text
    assert secret_content not in audit_text
    assert req.request_id in audit_text
    assert req.request_sha256() in audit_text
