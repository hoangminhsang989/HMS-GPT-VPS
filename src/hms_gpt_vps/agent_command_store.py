from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from .agent_transport_codec import (
    parse_agent_command_result,
    parse_signed_agent_command,
)
from .agent_transport_protocol import (
    MAX_AGENT_BODY_BYTES,
    AgentCommandResult,
    SignedAgentCommand,
    _canonical_json,
)


MAX_PENDING_AGENT_COMMANDS_PER_INSTANCE = 128


class AgentCommandStoreError(RuntimeError):
    pass


class AgentCommandConflictError(AgentCommandStoreError):
    pass


class AgentCommandNotFoundError(AgentCommandStoreError):
    pass


class AgentCommandExpiredError(AgentCommandStoreError):
    pass


class AgentCommandQueueFullError(AgentCommandStoreError):
    pass


class AgentCommandState(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    EXPIRED = "expired"


@dataclass(frozen=True)
class AgentCommandStatus:
    instance_id: str
    request_id: str
    state: AgentCommandState
    result: AgentCommandResult | None = None


def _aware_utc(value: datetime | None = None) -> datetime:
    checked = value or datetime.now(timezone.utc)
    if checked.tzinfo is None or checked.utcoffset() is None:
        raise AgentCommandStoreError("Agent command store timestamp must be timezone-aware")
    return checked.astimezone(timezone.utc)


def _json_dict(raw: str, name: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AgentCommandStoreError(f"stored {name} JSON is corrupt") from exc
    if not isinstance(value, dict):
        raise AgentCommandStoreError(f"stored {name} must be an object")
    return value


def _verified_stored_result(
    result_json: object,
    result_sha256: object,
) -> AgentCommandResult:
    if not isinstance(result_json, str) or not isinstance(result_sha256, str):
        raise AgentCommandStoreError("completed Agent command result is incomplete")
    raw = result_json.encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != result_sha256.lower():
        raise AgentCommandStoreError("stored Agent result failed integrity check")
    return parse_agent_command_result(_json_dict(result_json, "Agent result"))


class AgentCommandStore:
    """Durable Bridge-side command/result queue.

    Commands remain PENDING until a matching result is durably accepted. Polls
    may therefore redeliver the same signed command after network loss; the
    Agent-side idempotency journal prevents duplicate side effects. Expired
    commands are marked EXPIRED and never returned to the Agent.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = path
        self.timeout_seconds = timeout_seconds
        if not self.path.parent.exists() or not self.path.parent.is_dir():
            raise AgentCommandStoreError(
                "Agent command store parent must already exist"
            )
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_commands (
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
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_agent_commands_pending
                ON agent_commands(instance_id, state, enqueued_unix, request_id)
                """
            )

    def enqueue(
        self,
        signed: SignedAgentCommand,
        *,
        now: datetime | None = None,
    ) -> AgentCommandStatus:
        command_dict = signed.to_dict()
        command = parse_signed_agent_command(command_dict).command
        checked_at = _aware_utc(now)
        deadline = command.deadline_at.astimezone(timezone.utc)
        if deadline <= checked_at:
            raise AgentCommandExpiredError("Agent command deadline has already expired")
        raw = _canonical_json(command_dict)
        if len(raw) > MAX_AGENT_BODY_BYTES:
            raise AgentCommandStoreError("signed Agent command exceeds transport size limit")
        command_json = raw.decode("utf-8")
        command_sha256 = hashlib.sha256(raw).hexdigest()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT state, command_sha256, result_json, result_sha256
                FROM agent_commands
                WHERE instance_id = ? AND request_id = ?
                """,
                (command.instance_id, command.request_id),
            ).fetchone()
            if existing is not None:
                if str(existing["command_sha256"]).lower() != command_sha256:
                    raise AgentCommandConflictError(
                        "request_id is already bound to a different Agent command"
                    )
                state = AgentCommandState(str(existing["state"]))
                result = None
                if state is AgentCommandState.COMPLETED:
                    result = _verified_stored_result(
                        existing["result_json"],
                        existing["result_sha256"],
                    )
                connection.execute("COMMIT")
                return AgentCommandStatus(
                    instance_id=command.instance_id,
                    request_id=command.request_id,
                    state=state,
                    result=result,
                )

            pending_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM agent_commands
                    WHERE instance_id = ? AND state = ?
                    """,
                    (command.instance_id, AgentCommandState.PENDING.value),
                ).fetchone()[0]
            )
            if pending_count >= MAX_PENDING_AGENT_COMMANDS_PER_INSTANCE:
                raise AgentCommandQueueFullError(
                    "Agent command queue reached the per-instance pending limit"
                )

            connection.execute(
                """
                INSERT INTO agent_commands(
                    instance_id, request_id, state, command_json,
                    command_sha256, deadline_unix, enqueued_unix
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    command.instance_id,
                    command.request_id,
                    AgentCommandState.PENDING.value,
                    command_json,
                    command_sha256,
                    deadline.timestamp(),
                    checked_at.timestamp(),
                ),
            )
            connection.execute("COMMIT")
            return AgentCommandStatus(
                instance_id=command.instance_id,
                request_id=command.request_id,
                state=AgentCommandState.PENDING,
            )
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def next_pending(
        self,
        instance_id: str,
        *,
        now: datetime | None = None,
    ) -> SignedAgentCommand | None:
        checked_at = _aware_utc(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE agent_commands
                SET state = ?
                WHERE instance_id = ? AND state = ? AND deadline_unix <= ?
                """,
                (
                    AgentCommandState.EXPIRED.value,
                    instance_id,
                    AgentCommandState.PENDING.value,
                    checked_at.timestamp(),
                ),
            )
            row = connection.execute(
                """
                SELECT command_json, command_sha256
                FROM agent_commands
                WHERE instance_id = ? AND state = ?
                ORDER BY enqueued_unix ASC, request_id ASC
                LIMIT 1
                """,
                (instance_id, AgentCommandState.PENDING.value),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            command_json = str(row["command_json"])
            raw = command_json.encode("utf-8")
            expected_hash = str(row["command_sha256"]).lower()
            if hashlib.sha256(raw).hexdigest() != expected_hash:
                raise AgentCommandStoreError(
                    "stored Agent command failed integrity check"
                )
            signed = parse_signed_agent_command(
                _json_dict(command_json, "Agent command")
            )
            connection.execute("COMMIT")
            return signed
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def complete(
        self,
        result: AgentCommandResult,
        *,
        now: datetime | None = None,
    ) -> AgentCommandStatus:
        result.validate()
        checked_at = _aware_utc(now)
        raw = _canonical_json(result.to_dict())
        if len(raw) > MAX_AGENT_BODY_BYTES:
            raise AgentCommandStoreError("Agent result exceeds transport size limit")
        result_json = raw.decode("utf-8")
        result_sha256 = hashlib.sha256(raw).hexdigest()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT state, result_json, result_sha256
                FROM agent_commands
                WHERE instance_id = ? AND request_id = ?
                """,
                (result.instance_id, result.request_id),
            ).fetchone()
            if row is None:
                raise AgentCommandNotFoundError(
                    "Agent result does not match a queued command"
                )
            state = AgentCommandState(str(row["state"]))
            if state is AgentCommandState.EXPIRED:
                raise AgentCommandExpiredError(
                    "Agent result arrived after command expiration"
                )
            if state is AgentCommandState.COMPLETED:
                cached = _verified_stored_result(
                    row["result_json"],
                    row["result_sha256"],
                )
                existing_hash = str(row["result_sha256"]).lower()
                if existing_hash != result_sha256:
                    raise AgentCommandConflictError(
                        "Agent command already has a different completed result"
                    )
                connection.execute("COMMIT")
                return AgentCommandStatus(
                    instance_id=result.instance_id,
                    request_id=result.request_id,
                    state=AgentCommandState.COMPLETED,
                    result=cached,
                )

            connection.execute(
                """
                UPDATE agent_commands
                SET state = ?, result_json = ?, result_sha256 = ?, completed_unix = ?
                WHERE instance_id = ? AND request_id = ?
                """,
                (
                    AgentCommandState.COMPLETED.value,
                    result_json,
                    result_sha256,
                    checked_at.timestamp(),
                    result.instance_id,
                    result.request_id,
                ),
            )
            connection.execute("COMMIT")
            return AgentCommandStatus(
                instance_id=result.instance_id,
                request_id=result.request_id,
                state=AgentCommandState.COMPLETED,
                result=result,
            )
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def get_status(self, instance_id: str, request_id: str) -> AgentCommandStatus | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT state, result_json, result_sha256
                FROM agent_commands
                WHERE instance_id = ? AND request_id = ?
                """,
                (instance_id, request_id),
            ).fetchone()
        if row is None:
            return None
        state = AgentCommandState(str(row["state"]))
        result = None
        if state is AgentCommandState.COMPLETED:
            result = _verified_stored_result(
                row["result_json"],
                row["result_sha256"],
            )
        return AgentCommandStatus(
            instance_id=instance_id,
            request_id=request_id,
            state=state,
            result=result,
        )
