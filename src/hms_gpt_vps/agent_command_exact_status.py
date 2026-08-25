from __future__ import annotations

import hashlib

from .agent_command_store import (
    AgentCommandConflictError,
    AgentCommandStatus,
    AgentCommandStore,
)
from .agent_transport_protocol import AgentCommandEnvelope, _canonical_json


def get_exact_agent_command_status(
    store: AgentCommandStore,
    command: AgentCommandEnvelope,
) -> AgentCommandStatus | None:
    """Read one queue row only if it is bound to the exact unsigned command.

    This is intentionally read-only. It reuses AgentCommandStore's hardened
    connection and row validators, then compares the canonical stored command
    body (including approved_command_sha256) to the caller's exact envelope.
    It never creates, activates, expires or completes a command.
    """

    if not isinstance(store, AgentCommandStore):
        raise TypeError("store must be an AgentCommandStore")
    command.validate()
    expected_dict = command.to_dict()
    expected_raw = _canonical_json(expected_dict)
    expected_sha256 = hashlib.sha256(expected_raw).hexdigest()

    with store._connection() as connection:
        store._validate_instance_states(connection, command.instance_id)
        row = connection.execute(
            """
            SELECT state, command_json, command_sha256, deadline_unix,
                   enqueued_unix, result_json, result_sha256, completed_unix
            FROM agent_commands
            WHERE instance_id = ? AND request_id = ?
            """,
            (command.instance_id, command.request_id),
        ).fetchone()
        if row is None:
            return None
        state, stored_signed, result = store._validate_row_consistency(
            row,
            instance_id=command.instance_id,
            request_id=command.request_id,
        )
        stored_raw = _canonical_json(stored_signed.command.to_dict())
        stored_sha256 = hashlib.sha256(stored_raw).hexdigest()
        if stored_sha256 != expected_sha256 or stored_signed.command.to_dict() != expected_dict:
            raise AgentCommandConflictError(
                "request_id is already bound to a different Agent command"
            )
        return AgentCommandStatus(
            instance_id=command.instance_id,
            request_id=command.request_id,
            state=state,
            result=result,
        )
