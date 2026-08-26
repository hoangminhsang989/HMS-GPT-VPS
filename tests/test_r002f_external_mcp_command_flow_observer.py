from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from hms_gpt_vps.agent_command_store import AgentCommandState
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
    AgentCommandResult,
    SignedAgentCommand,
)
from hms_gpt_vps.control_request import CONTROL_REQUEST_SCHEMA_VERSION, ControlRequest
from hms_gpt_vps.control_session import SESSION_SCHEMA_VERSION, ControlSessionRecord
from hms_gpt_vps.external_mcp_command_flow_observer import (
    EXTERNAL_MCP_READ_CHALLENGE_SCHEMA_VERSION,
    ExternalMcpCommandFlowObservationError,
    ExternalMcpReadChallenge,
    observe_external_mcp_read_durable_authority,
)
from hms_gpt_vps.pairing import PAIRING_SCHEMA_VERSION, PairingRecord
from hms_gpt_vps.principal_dispatch_intent import (
    PRINCIPAL_DISPATCH_INTENT_SCHEMA_VERSION,
    PrincipalDispatchIntent,
)
from hms_gpt_vps.principal_pairing_service import (
    PRINCIPAL_SESSION_BINDING_SCHEMA_VERSION,
    PrincipalSessionBinding,
)


INSTANCE_ID = "instance-r002f-external-read"
REQUEST_ID = "r002f-external-read-001"
CHALLENGE_ID = "challenge-r002f-external-read-001"
PAIR_ID = "pair-r002f-external-read"
SESSION_ID = "session-r002f-external-read"
FAMILY_ID = "family-r002f-external-read"
PRINCIPAL_SHA256 = "2" * 64
SESSION_TOKEN = "session-token-r002f-external-read"
SOURCE_COMMIT = "4" * 40
PATH = "proof/external-mcp-read.txt"
CONTENT = b"HMS GPT VPS external MCP durable read proof\n"
CONTENT_SHA256 = hashlib.sha256(CONTENT).hexdigest()
INGRESS_GENERATION = "a" * 32
BASE = datetime(2026, 8, 26, 5, 0, tzinfo=timezone.utc)
SESSION_ISSUED = BASE - timedelta(minutes=4)
SESSION_EXPIRES = BASE + timedelta(minutes=56)


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def _challenge(**changes) -> ExternalMcpReadChallenge:
    values = {
        "schema_version": EXTERNAL_MCP_READ_CHALLENGE_SCHEMA_VERSION,
        "challenge_id": CHALLENGE_ID,
        "source_commit": SOURCE_COMMIT,
        "instance_id": INSTANCE_ID,
        "request_id": REQUEST_ID,
        "path": PATH,
        "expected_content_sha256": CONTENT_SHA256,
        "issued_at": BASE,
        "expires_at": BASE + timedelta(minutes=10),
    }
    values.update(changes)
    return ExternalMcpReadChallenge(**values)


def _session_record() -> ControlSessionRecord:
    return ControlSessionRecord(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id=SESSION_ID,
        family_id=FAMILY_ID,
        instance_id=INSTANCE_ID,
        token_sha256=hashlib.sha256(SESSION_TOKEN.encode("utf-8")).hexdigest(),
        scopes=("workspace.read",),
        issued_at=SESSION_ISSUED,
        expires_at=SESSION_EXPIRES,
        epoch=1,
    )


def _binding() -> PrincipalSessionBinding:
    session = _session_record()
    return PrincipalSessionBinding(
        schema_version=PRINCIPAL_SESSION_BINDING_SCHEMA_VERSION,
        principal_sha256=PRINCIPAL_SHA256,
        instance_id=INSTANCE_ID,
        pair_id=PAIR_ID,
        session_id=SESSION_ID,
        family_id=FAMILY_ID,
        session_token_sha256=session.token_sha256,
        scopes=session.scopes,
        issued_at=session.issued_at,
        expires_at=session.expires_at,
        epoch=session.epoch,
        session_token=SESSION_TOKEN,
    )


def _pairing_record() -> PairingRecord:
    return PairingRecord(
        schema_version=PAIRING_SCHEMA_VERSION,
        pair_id=PAIR_ID,
        instance_id=INSTANCE_ID,
        token_sha256="3" * 64,
        scopes=("workspace.read",),
        issued_at=BASE - timedelta(minutes=6),
        expires_at=BASE + timedelta(minutes=4),
        consumed_at=BASE - timedelta(minutes=5),
        revoked_at=None,
    )


def _command(action: str = "workspace.read", params=None) -> AgentCommandEnvelope:
    return AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id=REQUEST_ID,
        instance_id=INSTANCE_ID,
        action=action,
        params={"path": PATH} if params is None else params,
        deadline_at=SESSION_EXPIRES,
        approved_command_sha256=None,
    )


def _result(response=None) -> AgentCommandResult:
    payload = {
        "ok": True,
        "path": PATH,
        "encoding": "utf-8",
        "content": CONTENT.decode("utf-8"),
        "size": len(CONTENT),
        "sha256": CONTENT_SHA256,
        "modified_utc": "2026-08-26T04:59:00+00:00",
    }
    if response is not None:
        payload = response
    return AgentCommandResult(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id=REQUEST_ID,
        instance_id=INSTANCE_ID,
        outcome="ok",
        response=payload,
        completed_at=BASE + timedelta(minutes=1),
    )


def _write_authority(
    root: Path,
    *,
    command: AgentCommandEnvelope | None = None,
    result: AgentCommandResult | None = None,
    idempotency_state: str = "completed",
    receipt_override: dict[str, object] | None = None,
    ingress_generation: str | None = INGRESS_GENERATION,
) -> PrincipalDispatchIntent:
    command = command or _command()
    result = result or _result()
    signed = SignedAgentCommand(command=command, signature="a" * 64)
    request = ControlRequest(
        schema_version=CONTROL_REQUEST_SCHEMA_VERSION,
        request_id=REQUEST_ID,
        instance_id=INSTANCE_ID,
        session_id=SESSION_ID,
        action="workspace.read",
        params={"path": PATH},
    )
    intent = PrincipalDispatchIntent(
        schema_version=PRINCIPAL_DISPATCH_INTENT_SCHEMA_VERSION,
        principal_sha256=PRINCIPAL_SHA256,
        pair_id=PAIR_ID,
        session_id=SESSION_ID,
        session_epoch=1,
        instance_id=INSTANCE_ID,
        request_id=REQUEST_ID,
        request_sha256=request.request_sha256(),
        command_sha256=_sha(command.to_dict()),
        expires_at=SESSION_EXPIRES,
    )

    db_dir = root / "db"
    secrets_dir = root / "secrets"
    (secrets_dir / "principal-bindings").mkdir(parents=True)
    db_dir.mkdir()

    auth = _db(db_dir / "pairing-control.sqlite3")
    auth.executescript(
        """
        CREATE TABLE pairing_records (
            pair_id TEXT PRIMARY KEY NOT NULL,
            instance_id TEXT NOT NULL,
            record_json TEXT NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE control_sessions (
            session_id TEXT PRIMARY KEY NOT NULL,
            family_id TEXT NOT NULL,
            instance_id TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            record_json TEXT NOT NULL,
            UNIQUE(family_id, epoch)
        ) WITHOUT ROWID;
        """
    )
    pairing = _pairing_record()
    auth.execute(
        "INSERT INTO pairing_records(pair_id, instance_id, record_json) VALUES (?, ?, ?)",
        (PAIR_ID, INSTANCE_ID, _canonical(pairing.to_dict())),
    )
    session = _session_record()
    auth.execute(
        "INSERT INTO control_sessions(session_id, family_id, instance_id, epoch, record_json) VALUES (?, ?, ?, ?, ?)",
        (SESSION_ID, FAMILY_ID, INSTANCE_ID, 1, _canonical(session.to_dict())),
    )
    auth.commit()
    auth.close()

    command_dict = signed.to_dict()
    command_json = _canonical(command_dict)
    result_json = _canonical(result.to_dict())
    commands = _db(db_dir / "agent-commands.sqlite3")
    commands.execute(
        """
        CREATE TABLE agent_commands (
            instance_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            state TEXT NOT NULL,
            command_json TEXT NOT NULL,
            command_sha256 TEXT NOT NULL,
            deadline_unix REAL NOT NULL,
            enqueued_unix REAL NOT NULL,
            result_json TEXT,
            result_sha256 TEXT,
            completed_unix REAL,
            PRIMARY KEY(instance_id, request_id)
        ) WITHOUT ROWID
        """
    )
    commands.execute(
        "INSERT INTO agent_commands VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            INSTANCE_ID,
            REQUEST_ID,
            AgentCommandState.COMPLETED.value,
            command_json,
            hashlib.sha256(command_json.encode("utf-8")).hexdigest(),
            SESSION_EXPIRES.timestamp(),
            BASE.timestamp(),
            result_json,
            hashlib.sha256(result_json.encode("utf-8")).hexdigest(),
            (BASE + timedelta(minutes=1)).timestamp(),
        ),
    )
    commands.commit()
    commands.close()

    receipt = {
        "schema_version": 1,
        "kind": "agent_completed",
        "instance_id": INSTANCE_ID,
        "request_id": REQUEST_ID,
        "command_sha256": _sha(command.to_dict()),
        "result_sha256": _sha(result.to_dict()),
    }
    if receipt_override is not None:
        receipt = receipt_override
    receipt_json = _canonical(receipt)
    idempotency = _db(db_dir / "control-idempotency.sqlite3")
    idempotency.executescript(
        """
        CREATE TABLE principal_agent_dispatch_claims (
            schema_version INTEGER NOT NULL,
            principal_sha256 TEXT NOT NULL,
            pair_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            session_epoch INTEGER NOT NULL,
            instance_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            command_sha256 TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY(session_id, request_id)
        ) WITHOUT ROWID;
        CREATE TABLE principal_dispatch_ingress_provenance (
            schema_version INTEGER NOT NULL,
            principal_sha256 TEXT NOT NULL,
            pair_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            session_epoch INTEGER NOT NULL,
            instance_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            command_sha256 TEXT NOT NULL,
            mcp_ingress_generation TEXT NOT NULL,
            PRIMARY KEY(session_id, request_id)
        ) WITHOUT ROWID;
        CREATE TABLE idempotency_records (
            session_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            state TEXT NOT NULL,
            response_json TEXT,
            response_sha256 TEXT,
            claimed_at TEXT NOT NULL,
            completed_at TEXT,
            PRIMARY KEY(session_id, request_id)
        ) WITHOUT ROWID;
        """
    )
    idempotency.execute(
        "INSERT INTO principal_agent_dispatch_claims VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        intent.to_row(),
    )
    if ingress_generation is not None:
        idempotency.execute(
            "INSERT INTO principal_dispatch_ingress_provenance VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                intent.principal_sha256,
                intent.pair_id,
                intent.session_id,
                intent.session_epoch,
                intent.instance_id,
                intent.request_id,
                intent.request_sha256,
                intent.command_sha256,
                ingress_generation,
            ),
        )
    if idempotency_state == "completed":
        idempotency.execute(
            "INSERT INTO idempotency_records VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                SESSION_ID,
                REQUEST_ID,
                intent.request_sha256,
                "completed",
                receipt_json,
                hashlib.sha256(receipt_json.encode("utf-8")).hexdigest(),
                BASE.isoformat().replace("+00:00", "Z"),
                (BASE + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            ),
        )
    else:
        idempotency.execute(
            "INSERT INTO idempotency_records VALUES (?, ?, ?, ?, NULL, NULL, ?, NULL)",
            (
                SESSION_ID,
                REQUEST_ID,
                intent.request_sha256,
                "claimed",
                BASE.isoformat().replace("+00:00", "Z"),
            ),
        )
    idempotency.commit()
    idempotency.close()
    return intent


def _loader(binding: PrincipalSessionBinding):
    def load(root: Path, principal_sha256: str, instance_id: str) -> PrincipalSessionBinding:
        assert root.name == "principal-bindings"
        assert principal_sha256 == PRINCIPAL_SHA256
        assert instance_id == INSTANCE_ID
        return binding

    return load


def _database_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in sorted((root / "db").iterdir())
        if path.is_file()
    }


def test_external_mcp_durable_read_observer_accepts_exact_chain_read_only(tmp_path: Path) -> None:
    _write_authority(tmp_path)
    before = _database_bytes(tmp_path)

    proof = observe_external_mcp_read_durable_authority(
        tmp_path,
        _challenge(),
        binding_loader=_loader(_binding()),
        now=BASE + timedelta(minutes=2),
    )

    assert proof["ready"] is True
    assert proof["status"] == "PRINCIPAL_BOUND_READ_DURABLE_AUTHORITY_OBSERVED"
    assert proof["authenticated_principal_control_path_proven"] is True
    assert proof["agent_command_action"] == "workspace.read"
    assert proof["workspace_content_size"] == len(CONTENT)
    assert proof["expected_content_sha256"] == CONTENT_SHA256
    assert proof["mcp_ingress_provenance_present"] is True
    assert proof["mcp_ingress_generation"] == INGRESS_GENERATION
    assert proof["mcp_adapter_invocation_proven"] is True
    assert proof["openai_control_plane_origin_proven"] is False
    assert proof["secure_tunnel_generation_proven"] is False
    assert proof["full_bridge_command_flow_proven"] is False
    assert _database_bytes(tmp_path) == before


def test_challenge_rejects_noncanonical_path_and_long_lifetime() -> None:
    with pytest.raises(ExternalMcpCommandFlowObservationError):
        _challenge(path="proof\\read.txt").validate()
    with pytest.raises(ExternalMcpCommandFlowObservationError):
        _challenge(expires_at=BASE + timedelta(minutes=16)).validate()


def test_observer_rejects_duplicate_dispatch_for_same_challenge(tmp_path: Path) -> None:
    intent = _write_authority(tmp_path)
    db = _db(tmp_path / "db" / "control-idempotency.sqlite3")
    duplicate = replace(intent, session_id="session-r002f-external-read-duplicate")
    db.execute(
        "INSERT INTO principal_agent_dispatch_claims VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        duplicate.to_row(),
    )
    db.commit()
    db.close()
    with pytest.raises(ExternalMcpCommandFlowObservationError, match="exactly one"):
        observe_external_mcp_read_durable_authority(
            tmp_path, _challenge(), binding_loader=_loader(_binding()), now=BASE + timedelta(minutes=2)
        )


def test_observer_rejects_claimed_not_completed_idempotency(tmp_path: Path) -> None:
    _write_authority(tmp_path, idempotency_state="claimed")
    with pytest.raises(ExternalMcpCommandFlowObservationError, match="completed"):
        observe_external_mcp_read_durable_authority(
            tmp_path, _challenge(), binding_loader=_loader(_binding()), now=BASE + timedelta(minutes=2)
        )


def test_observer_rejects_binding_session_drift(tmp_path: Path) -> None:
    _write_authority(tmp_path)
    bad = replace(_binding(), family_id="family-r002f-external-read-drift")
    with pytest.raises(ExternalMcpCommandFlowObservationError, match="differ"):
        observe_external_mcp_read_durable_authority(
            tmp_path, _challenge(), binding_loader=_loader(bad), now=BASE + timedelta(minutes=2)
        )


def test_observer_rejects_agent_action_drift_even_when_intent_digest_matches(tmp_path: Path) -> None:
    command = _command(action="git.status", params={})
    _write_authority(tmp_path, command=command)
    with pytest.raises(ExternalMcpCommandFlowObservationError):
        observe_external_mcp_read_durable_authority(
            tmp_path, _challenge(), binding_loader=_loader(_binding()), now=BASE + timedelta(minutes=2)
        )


def test_observer_rejects_completion_receipt_digest_drift(tmp_path: Path) -> None:
    result = _result()
    receipt = {
        "schema_version": 1,
        "kind": "agent_completed",
        "instance_id": INSTANCE_ID,
        "request_id": REQUEST_ID,
        "command_sha256": _sha(_command().to_dict()),
        "result_sha256": "f" * 64,
    }
    _write_authority(tmp_path, result=result, receipt_override=receipt)
    with pytest.raises(ExternalMcpCommandFlowObservationError, match="receipt"):
        observe_external_mcp_read_durable_authority(
            tmp_path, _challenge(), binding_loader=_loader(_binding()), now=BASE + timedelta(minutes=2)
        )


def test_observer_rejects_content_hash_drift(tmp_path: Path) -> None:
    response = dict(_result().response)
    response["content"] = "different bytes\n"
    response["size"] = len(response["content"].encode("utf-8"))
    response["sha256"] = hashlib.sha256(response["content"].encode("utf-8")).hexdigest()
    _write_authority(tmp_path, result=_result(response))
    with pytest.raises(ExternalMcpCommandFlowObservationError, match="challenge authority"):
        observe_external_mcp_read_durable_authority(
            tmp_path, _challenge(), binding_loader=_loader(_binding()), now=BASE + timedelta(minutes=2)
        )


def test_observer_rejects_binding_drift_during_reobservation(tmp_path: Path) -> None:
    _write_authority(tmp_path)
    values = [_binding(), replace(_binding(), family_id="family-r002f-external-read-drift")]

    def drifting_loader(root: Path, principal_sha256: str, instance_id: str) -> PrincipalSessionBinding:
        assert root.name == "principal-bindings"
        assert principal_sha256 == PRINCIPAL_SHA256
        assert instance_id == INSTANCE_ID
        return values.pop(0)

    with pytest.raises(ExternalMcpCommandFlowObservationError):
        observe_external_mcp_read_durable_authority(
            tmp_path,
            _challenge(),
            binding_loader=drifting_loader,
            now=BASE + timedelta(minutes=2),
        )


def test_observer_rejects_missing_mcp_ingress_provenance(tmp_path: Path) -> None:
    _write_authority(tmp_path, ingress_generation=None)
    with pytest.raises(ExternalMcpCommandFlowObservationError, match="provenance"):
        observe_external_mcp_read_durable_authority(
            tmp_path, _challenge(), binding_loader=_loader(_binding()), now=BASE + timedelta(minutes=2)
        )


def test_observer_rejects_ingress_provenance_digest_drift(tmp_path: Path) -> None:
    _write_authority(tmp_path)
    db = _db(tmp_path / "db" / "control-idempotency.sqlite3")
    db.execute(
        "UPDATE principal_dispatch_ingress_provenance SET command_sha256 = ? WHERE request_id = ?",
        ("f" * 64, REQUEST_ID),
    )
    db.commit()
    db.close()
    with pytest.raises(ExternalMcpCommandFlowObservationError, match="provenance"):
        observe_external_mcp_read_durable_authority(
            tmp_path, _challenge(), binding_loader=_loader(_binding()), now=BASE + timedelta(minutes=2)
        )
