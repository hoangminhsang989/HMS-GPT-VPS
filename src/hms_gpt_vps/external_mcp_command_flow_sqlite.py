from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat

from .agent_command_store import AgentCommandState, AgentCommandStore
from .control_session import ControlSessionRecord
from .control_session_store import ControlSessionStore
from .external_mcp_command_flow_contract import (
    ExternalMcpCommandFlowObservationError,
    ExternalMcpReadChallenge,
    READ_ACTION,
)
from .idempotency_store import IdempotencyState, IdempotencyStore
from .pairing import PairingRecord
from .pairing_store import PairingStore
from .principal_dispatch_ingress_provenance import McpIngressDispatchProvenance
from .principal_dispatch_intent import PrincipalDispatchIntent
from .qualification_file_authority import lexical_absolute, path_chain_has_redirect


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _require_existing_regular_file(path: Path, label: str) -> tuple[Path, os.stat_result]:
    authority = lexical_absolute(path)
    if path_chain_has_redirect(authority):
        raise ExternalMcpCommandFlowObservationError(
            f"{label} traverses a link or reparse point"
        )
    if not authority.parent.is_dir():
        raise ExternalMcpCommandFlowObservationError(
            f"{label} parent authority is unavailable"
        )
    try:
        current = authority.stat()
    except FileNotFoundError as exc:
        raise ExternalMcpCommandFlowObservationError(
            f"{label} is unavailable"
        ) from exc
    if not stat.S_ISREG(current.st_mode) or not authority.is_file():
        raise ExternalMcpCommandFlowObservationError(
            f"{label} must be a regular file"
        )
    return authority, current


@contextmanager
def read_only_connection(path: Path, *, label: str):
    authority, before = _require_existing_regular_file(path, label)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            authority.as_uri() + "?mode=ro",
            uri=True,
            timeout=5.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("BEGIN")
        after_open = _require_existing_regular_file(authority, label)[1]
        if not _same_file_identity(before, after_open):
            raise ExternalMcpCommandFlowObservationError(
                f"{label} identity changed during read-only SQLite open"
            )
        yield connection
        after_query = _require_existing_regular_file(authority, label)[1]
        if not _same_file_identity(before, after_query):
            raise ExternalMcpCommandFlowObservationError(
                f"{label} identity changed during read-only transaction"
            )
    except sqlite3.Error as exc:
        raise ExternalMcpCommandFlowObservationError(
            f"{label} read-only SQLite transaction failed"
        ) from exc
    finally:
        if connection is not None:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            connection.close()
        after_close = _require_existing_regular_file(authority, label)[1]
        if not _same_file_identity(before, after_close):
            raise ExternalMcpCommandFlowObservationError(
                f"{label} identity changed across read-only observation"
            )


def query_rows(
    connection: sqlite3.Connection,
    query: str,
    params: tuple[object, ...],
) -> list[sqlite3.Row]:
    try:
        return connection.execute(query, params).fetchall()
    except sqlite3.Error as exc:
        raise ExternalMcpCommandFlowObservationError(
            "read-only authority query failed"
        ) from exc


def load_dispatch_and_receipt(
    idempotency_db: Path,
    challenge: ExternalMcpReadChallenge,
) -> tuple[PrincipalDispatchIntent, dict[str, object]]:
    with read_only_connection(
        idempotency_db,
        label="principal dispatch authority database",
    ) as connection:
        dispatch_rows = query_rows(
            connection,
            """
            SELECT schema_version, principal_sha256, pair_id, session_id,
                   session_epoch, instance_id, request_id, request_sha256,
                   command_sha256, expires_at
            FROM principal_agent_dispatch_claims
            WHERE instance_id = ? AND request_id = ?
            """,
            (challenge.instance_id, challenge.request_id),
        )
        if len(dispatch_rows) != 1:
            raise ExternalMcpCommandFlowObservationError(
                "challenge must resolve to exactly one principal dispatch intent"
            )
        try:
            intent = PrincipalDispatchIntent.from_row(dispatch_rows[0])
        except Exception as exc:
            raise ExternalMcpCommandFlowObservationError(
                "principal dispatch intent failed exact validation"
            ) from exc

        idempotency_rows = query_rows(
            connection,
            """
            SELECT request_sha256, state, response_json, response_sha256,
                   claimed_at, completed_at
            FROM idempotency_records
            WHERE session_id = ? AND request_id = ?
            """,
            (intent.session_id, intent.request_id),
        )
        if len(idempotency_rows) != 1:
            raise ExternalMcpCommandFlowObservationError(
                "principal dispatch intent lacks one exact idempotency record"
            )
        try:
            state, receipt = IdempotencyStore._validate_row(
                idempotency_rows[0],
                expected_request_sha256=intent.request_sha256,
            )
        except Exception as exc:
            raise ExternalMcpCommandFlowObservationError(
                "principal idempotency record failed exact validation"
            ) from exc
    if state is not IdempotencyState.COMPLETED or not isinstance(receipt, dict):
        raise ExternalMcpCommandFlowObservationError(
            "principal read request has not reached durable completed state"
        )
    return intent, dict(receipt)


def load_dispatch_provenance_and_receipt(
    idempotency_db: Path,
    challenge: ExternalMcpReadChallenge,
) -> tuple[PrincipalDispatchIntent, McpIngressDispatchProvenance, dict[str, object]]:
    """Load one completed dispatch and its atomic protected-MCP provenance snapshot."""

    with read_only_connection(
        idempotency_db,
        label="principal dispatch authority database",
    ) as connection:
        dispatch_rows = query_rows(
            connection,
            """
            SELECT schema_version, principal_sha256, pair_id, session_id,
                   session_epoch, instance_id, request_id, request_sha256,
                   command_sha256, expires_at
            FROM principal_agent_dispatch_claims
            WHERE instance_id = ? AND request_id = ?
            """,
            (challenge.instance_id, challenge.request_id),
        )
        if len(dispatch_rows) != 1:
            raise ExternalMcpCommandFlowObservationError(
                "challenge must resolve to exactly one principal dispatch intent"
            )
        try:
            intent = PrincipalDispatchIntent.from_row(dispatch_rows[0])
        except Exception as exc:
            raise ExternalMcpCommandFlowObservationError(
                "principal dispatch intent failed exact validation"
            ) from exc

        provenance_rows = query_rows(
            connection,
            """
            SELECT schema_version, principal_sha256, pair_id, session_id,
                   session_epoch, instance_id, request_id, request_sha256,
                   command_sha256, mcp_ingress_generation
            FROM principal_dispatch_ingress_provenance
            WHERE session_id = ? AND request_id = ?
            """,
            (intent.session_id, intent.request_id),
        )
        if len(provenance_rows) != 1:
            raise ExternalMcpCommandFlowObservationError(
                "principal dispatch lacks one exact protected MCP ingress provenance row"
            )
        try:
            provenance = McpIngressDispatchProvenance.from_row(provenance_rows[0])
            provenance.require_exact_intent(intent)
        except Exception as exc:
            raise ExternalMcpCommandFlowObservationError(
                "protected MCP ingress provenance failed exact dispatch validation"
            ) from exc

        idempotency_rows = query_rows(
            connection,
            """
            SELECT request_sha256, state, response_json, response_sha256,
                   claimed_at, completed_at
            FROM idempotency_records
            WHERE session_id = ? AND request_id = ?
            """,
            (intent.session_id, intent.request_id),
        )
        if len(idempotency_rows) != 1:
            raise ExternalMcpCommandFlowObservationError(
                "principal dispatch intent lacks one exact idempotency record"
            )
        try:
            state, receipt = IdempotencyStore._validate_row(
                idempotency_rows[0],
                expected_request_sha256=intent.request_sha256,
            )
        except Exception as exc:
            raise ExternalMcpCommandFlowObservationError(
                "principal idempotency record failed exact validation"
            ) from exc
    if state is not IdempotencyState.COMPLETED or not isinstance(receipt, dict):
        raise ExternalMcpCommandFlowObservationError(
            "principal read request has not reached durable completed state"
        )
    return intent, provenance, dict(receipt)


def load_pairing_and_control_session(
    auth_db: Path,
    intent: PrincipalDispatchIntent,
) -> tuple[PairingRecord, ControlSessionRecord]:
    with read_only_connection(
        auth_db,
        label="pairing and control-session authority database",
    ) as connection:
        pairing_rows = query_rows(
            connection,
            "SELECT pair_id, instance_id, record_json FROM pairing_records WHERE pair_id = ?",
            (intent.pair_id,),
        )
        session_rows = query_rows(
            connection,
            """
            SELECT session_id, family_id, instance_id, epoch, record_json
            FROM control_sessions WHERE session_id = ?
            """,
            (intent.session_id,),
        )

    if (
        len(pairing_rows) != 1
        or set(pairing_rows[0].keys()) != {"pair_id", "instance_id", "record_json"}
    ):
        raise ExternalMcpCommandFlowObservationError(
            "principal dispatch lacks one exact pairing record"
        )
    pairing_row = pairing_rows[0]
    try:
        pairing = PairingStore._deserialize(pairing_row["record_json"])
    except Exception as exc:
        raise ExternalMcpCommandFlowObservationError(
            "pairing record failed exact validation"
        ) from exc
    if (
        pairing_row["pair_id"] != pairing.pair_id
        or pairing_row["instance_id"] != pairing.instance_id
        or pairing.pair_id != intent.pair_id
        or pairing.instance_id != intent.instance_id
        or pairing.consumed_at is None
        or pairing.revoked_at is not None
        or READ_ACTION not in pairing.scopes
    ):
        raise ExternalMcpCommandFlowObservationError(
            "pairing record does not authorize the observed read dispatch"
        )

    if len(session_rows) != 1:
        raise ExternalMcpCommandFlowObservationError(
            "principal dispatch lacks one exact control session"
        )
    try:
        session = ControlSessionStore._record_from_row(
            session_rows[0],
            expected_session_id=intent.session_id,
        )
    except Exception as exc:
        raise ExternalMcpCommandFlowObservationError(
            "control session failed exact validation"
        ) from exc
    if (
        session.instance_id != intent.instance_id
        or session.epoch != intent.session_epoch
        or session.revoked_at is not None
        or READ_ACTION not in session.scopes
    ):
        raise ExternalMcpCommandFlowObservationError(
            "control session does not authorize the observed read dispatch"
        )
    return pairing, session


def load_completed_agent_command(
    command_db: Path,
    challenge: ExternalMcpReadChallenge,
):
    with read_only_connection(
        command_db,
        label="Agent command authority database",
    ) as connection:
        rows = query_rows(
            connection,
            """
            SELECT state, command_json, command_sha256, deadline_unix,
                   enqueued_unix, result_json, result_sha256, completed_unix
            FROM agent_commands WHERE instance_id = ? AND request_id = ?
            """,
            (challenge.instance_id, challenge.request_id),
        )
    if len(rows) != 1:
        raise ExternalMcpCommandFlowObservationError(
            "challenge lacks one exact Agent command row"
        )
    try:
        state, signed, result = AgentCommandStore._validate_row_consistency(
            rows[0],
            instance_id=challenge.instance_id,
            request_id=challenge.request_id,
        )
    except Exception as exc:
        raise ExternalMcpCommandFlowObservationError(
            "Agent command row failed exact validation"
        ) from exc
    if state is not AgentCommandState.COMPLETED or result is None:
        raise ExternalMcpCommandFlowObservationError(
            "Agent command has not reached durable completed state"
        )
    return signed, result
