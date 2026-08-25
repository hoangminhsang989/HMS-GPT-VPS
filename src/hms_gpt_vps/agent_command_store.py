from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any, Iterator

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


AGENT_COMMAND_STORE_SCHEMA_VERSION = 1
MAX_PENDING_AGENT_COMMANDS_PER_INSTANCE = 128
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_AGENT_COMMAND_STORE_TIMEOUT_SECONDS = 30.0
_HEX_LOWER = frozenset("0123456789abcdef")


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
    if (
        not isinstance(checked, datetime)
        or checked.tzinfo is None
        or checked.utcoffset() is None
    ):
        raise AgentCommandStoreError(
            "Agent command store timestamp must be timezone-aware"
        )
    return checked.astimezone(timezone.utc)


def _path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = path.expanduser().absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            return True
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = int(getattr(info, "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    return False


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _no_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AgentCommandStoreError(
                f"stored Agent command authority has duplicate JSON key: {key}"
            )
        result[key] = value
    return result


def _strict_json_dict(raw: object, name: str) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise AgentCommandStoreError(f"stored {name} must be JSON text")
    encoded = raw.encode("utf-8")
    if not encoded or len(encoded) > MAX_AGENT_BODY_BYTES:
        raise AgentCommandStoreError(f"stored {name} size is invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise AgentCommandStoreError(f"stored {name} JSON is corrupt") from exc
    if not isinstance(value, dict):
        raise AgentCommandStoreError(f"stored {name} must be an object")
    return value


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AgentCommandStoreError(f"stored {name} must be a non-empty string")
    return value


def _require_sha256(value: object, name: str) -> str:
    digest = _require_text(value, name)
    if (
        len(digest) != 64
        or digest != digest.lower()
        or any(char not in _HEX_LOWER for char in digest)
    ):
        raise AgentCommandStoreError(
            f"stored {name} must be canonical lowercase SHA-256"
        )
    return digest


def _require_state(value: object) -> AgentCommandState:
    state_text = _require_text(value, "Agent command state")
    try:
        return AgentCommandState(state_text)
    except ValueError as exc:
        raise AgentCommandStoreError(
            f"unsupported Agent command state: {state_text}"
        ) from exc


def _require_finite_number(value: object, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise AgentCommandStoreError(f"stored {name} must be a finite number")
    return float(value)


def _verify_hash(raw_text: str, digest: str, name: str) -> None:
    if hashlib.sha256(raw_text.encode("utf-8")).hexdigest() != digest:
        raise AgentCommandStoreError(f"stored {name} failed integrity check")


def _verified_stored_result(
    result_json: object,
    result_sha256: object,
    *,
    expected_instance_id: str,
    expected_request_id: str,
) -> AgentCommandResult:
    raw_text = _require_text(result_json, "Agent result JSON")
    digest = _require_sha256(result_sha256, "Agent result SHA-256")
    _verify_hash(raw_text, digest, "Agent result")
    result = parse_agent_command_result(
        _strict_json_dict(raw_text, "Agent result")
    )
    if (
        result.instance_id != expected_instance_id
        or result.request_id != expected_request_id
    ):
        raise AgentCommandStoreError(
            "stored Agent result identity differs from queue authority"
        )
    return result


def _verified_stored_command(
    command_json: object,
    command_sha256: object,
    *,
    expected_instance_id: str,
    expected_request_id: str,
) -> SignedAgentCommand:
    raw_text = _require_text(command_json, "Agent command JSON")
    digest = _require_sha256(command_sha256, "Agent command SHA-256")
    _verify_hash(raw_text, digest, "Agent command")
    signed = parse_signed_agent_command(
        _strict_json_dict(raw_text, "Agent command")
    )
    command = signed.command
    if (
        command.instance_id != expected_instance_id
        or command.request_id != expected_request_id
    ):
        raise AgentCommandStoreError(
            "stored Agent command identity differs from queue authority"
        )
    return signed


def _require_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError(f"{name} is invalid")
    return value


class AgentCommandStore:
    """Durable Bridge-side command/result queue.

    Commands remain PENDING until a matching result is durably accepted. Polls
    may therefore redeliver the same signed command after network loss; the
    Agent-side idempotency journal prevents duplicate side effects. Expired
    commands are marked EXPIRED and never returned to the Agent.

    The main SQLite file is security authority: the lexical path may not traverse
    a symlink/junction/reparse point, the parent must already exist, and every
    operation must retain the exact regular-file identity pinned at startup.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds)
            <= _MAX_AGENT_COMMAND_STORE_TIMEOUT_SECONDS
        ):
            raise ValueError("timeout_seconds must be finite and between 0 and 30")
        self.path = path.expanduser().absolute()
        self.timeout_seconds = float(timeout_seconds)
        self._prepare_database_authority()
        self._database_identity = self._assert_authority()
        self._initialize()

    def _assert_authority(self) -> os.stat_result:
        if _path_chain_has_redirect(self.path):
            raise AgentCommandStoreError(
                "Agent command store authority path traverses a link or reparse point"
            )
        if not self.path.parent.is_dir():
            raise AgentCommandStoreError(
                "Agent command store parent authority is not a directory"
            )
        try:
            current = self.path.stat()
        except FileNotFoundError as exc:
            raise AgentCommandStoreError(
                "Agent command store database disappeared"
            ) from exc
        if not stat.S_ISREG(current.st_mode) or not self.path.is_file():
            raise AgentCommandStoreError(
                "Agent command store authority is not a regular file"
            )
        return current

    def _prepare_database_authority(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise AgentCommandStoreError(
                "Agent command store authority path traverses a link or reparse point"
            )
        parent = self.path.parent
        if not parent.exists() or not parent.is_dir():
            raise AgentCommandStoreError(
                "Agent command store parent must already exist"
            )
        if not self.path.exists():
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            try:
                fd = os.open(self.path, flags, 0o600)
            except FileExistsError:
                pass
            else:
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        self._assert_authority()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        before = self._assert_authority()
        if not _same_file_identity(self._database_identity, before):
            raise AgentCommandStoreError(
                "Agent command store database identity differs from startup authority"
            )
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            after_open = self._assert_authority()
            if not _same_file_identity(before, after_open):
                raise AgentCommandStoreError(
                    "Agent command store authority changed during SQLite open"
                )
            yield connection
            after_use = self._assert_authority()
            if not _same_file_identity(before, after_use):
                raise AgentCommandStoreError(
                    "Agent command store authority changed during SQLite operation"
                )
            if not _same_file_identity(self._database_identity, after_use):
                raise AgentCommandStoreError(
                    "Agent command store database identity differs from startup authority"
                )
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if isinstance(version, bool) or not isinstance(version, int):
                raise AgentCommandStoreError(
                    "Agent command store schema version is not an integer"
                )
            if version not in {0, AGENT_COMMAND_STORE_SCHEMA_VERSION}:
                raise AgentCommandStoreError(
                    f"unsupported Agent command store schema: {version}"
                )
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
            if version == 0:
                connection.execute(
                    f"PRAGMA user_version = {AGENT_COMMAND_STORE_SCHEMA_VERSION}"
                )

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    @staticmethod
    def _validate_row_consistency(
        row: sqlite3.Row,
        *,
        instance_id: str,
        request_id: str,
    ) -> tuple[AgentCommandState, SignedAgentCommand, AgentCommandResult | None]:
        required = {
            "state",
            "command_json",
            "command_sha256",
            "deadline_unix",
            "enqueued_unix",
            "result_json",
            "result_sha256",
            "completed_unix",
        }
        actual = set(row.keys())
        if not required.issubset(actual) or not actual.issubset(required | {"request_id"}):
            raise AgentCommandStoreError(
                "stored Agent command row fields do not match authority schema"
            )
        state = _require_state(row["state"])
        signed = _verified_stored_command(
            row["command_json"],
            row["command_sha256"],
            expected_instance_id=instance_id,
            expected_request_id=request_id,
        )
        deadline_unix = _require_finite_number(
            row["deadline_unix"], "Agent command deadline"
        )
        enqueued_unix = _require_finite_number(
            row["enqueued_unix"], "Agent command enqueue time"
        )
        if deadline_unix <= enqueued_unix:
            raise AgentCommandStoreError(
                "stored Agent command deadline does not follow enqueue time"
            )

        result: AgentCommandResult | None = None
        if state is AgentCommandState.COMPLETED:
            completed_unix = _require_finite_number(
                row["completed_unix"], "Agent command completion time"
            )
            if completed_unix < enqueued_unix:
                raise AgentCommandStoreError(
                    "stored Agent command completion precedes enqueue time"
                )
            result = _verified_stored_result(
                row["result_json"],
                row["result_sha256"],
                expected_instance_id=instance_id,
                expected_request_id=request_id,
            )
        else:
            if (
                row["result_json"] is not None
                or row["result_sha256"] is not None
                or row["completed_unix"] is not None
            ):
                raise AgentCommandStoreError(
                    "non-completed Agent command contains completed-result authority"
                )
        return state, signed, result

    @staticmethod
    def _validate_instance_states(
        connection: sqlite3.Connection,
        instance_id: str,
    ) -> None:
        rows = connection.execute(
            "SELECT DISTINCT state FROM agent_commands WHERE instance_id = ?",
            (instance_id,),
        ).fetchall()
        for row in rows:
            if set(row.keys()) != {"state"}:
                raise AgentCommandStoreError(
                    "stored Agent command state row fields do not match authority schema"
                )
            _require_state(row["state"])

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
            raise AgentCommandExpiredError(
                "Agent command deadline has already expired"
            )
        raw = _canonical_json(command_dict)
        if len(raw) > MAX_AGENT_BODY_BYTES:
            raise AgentCommandStoreError(
                "signed Agent command exceeds transport size limit"
            )
        command_json = raw.decode("utf-8")
        command_sha256 = hashlib.sha256(raw).hexdigest()

        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_instance_states(connection, command.instance_id)
                existing = connection.execute(
                    """
                    SELECT state, command_json, command_sha256, deadline_unix,
                           enqueued_unix, result_json, result_sha256, completed_unix
                    FROM agent_commands
                    WHERE instance_id = ? AND request_id = ?
                    """,
                    (command.instance_id, command.request_id),
                ).fetchone()
                if existing is not None:
                    state, stored_signed, result = self._validate_row_consistency(
                        existing,
                        instance_id=command.instance_id,
                        request_id=command.request_id,
                    )
                    stored_raw = _canonical_json(stored_signed.to_dict())
                    if hashlib.sha256(stored_raw).hexdigest() != command_sha256:
                        raise AgentCommandConflictError(
                            "request_id is already bound to a different Agent command"
                        )
                    connection.execute("COMMIT")
                    return AgentCommandStatus(
                        instance_id=command.instance_id,
                        request_id=command.request_id,
                        state=state,
                        result=result,
                    )

                count_row = connection.execute(
                    """
                    SELECT COUNT(*) AS pending_count FROM agent_commands
                    WHERE instance_id = ? AND state = ?
                    """,
                    (
                        command.instance_id,
                        AgentCommandState.PENDING.value,
                    ),
                ).fetchone()
                pending_count = count_row["pending_count"]
                if (
                    isinstance(pending_count, bool)
                    or not isinstance(pending_count, int)
                    or pending_count < 0
                ):
                    raise AgentCommandStoreError(
                        "Agent command pending count is not an integer"
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
                self._rollback(connection)
                raise

    def next_pending(
        self,
        instance_id: str,
        *,
        now: datetime | None = None,
    ) -> SignedAgentCommand | None:
        checked_instance = _require_identifier(instance_id, "instance_id")
        checked_at = _aware_utc(now)

        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_instance_states(connection, checked_instance)
                rows = connection.execute(
                    """
                    SELECT request_id, state, command_json, command_sha256,
                           deadline_unix, enqueued_unix, result_json,
                           result_sha256, completed_unix
                    FROM agent_commands
                    WHERE instance_id = ? AND state = ?
                    """,
                    (
                        checked_instance,
                        AgentCommandState.PENDING.value,
                    ),
                ).fetchall()

                candidates: list[
                    tuple[float, str, sqlite3.Row, SignedAgentCommand]
                ] = []
                for row in rows:
                    request_id = _require_identifier(
                        row["request_id"], "stored request_id"
                    )
                    state, signed, result = self._validate_row_consistency(
                        row,
                        instance_id=checked_instance,
                        request_id=request_id,
                    )
                    if state is not AgentCommandState.PENDING or result is not None:
                        raise AgentCommandStoreError(
                            "pending Agent command query returned inconsistent state"
                        )
                    deadline_unix = _require_finite_number(
                        row["deadline_unix"], "Agent command deadline"
                    )
                    enqueued_unix = _require_finite_number(
                        row["enqueued_unix"], "Agent command enqueue time"
                    )
                    if deadline_unix <= checked_at.timestamp():
                        connection.execute(
                            """
                            UPDATE agent_commands
                            SET state = ?
                            WHERE instance_id = ? AND request_id = ? AND state = ?
                            """,
                            (
                                AgentCommandState.EXPIRED.value,
                                checked_instance,
                                request_id,
                                AgentCommandState.PENDING.value,
                            ),
                        )
                        continue
                    candidates.append(
                        (enqueued_unix, request_id, row, signed)
                    )

                candidates.sort(key=lambda item: (item[0], item[1]))
                connection.execute("COMMIT")
                if not candidates:
                    return None
                return candidates[0][3]
            except Exception:
                self._rollback(connection)
                raise

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
            raise AgentCommandStoreError(
                "Agent result exceeds transport size limit"
            )
        result_json = raw.decode("utf-8")
        result_sha256 = hashlib.sha256(raw).hexdigest()

        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_instance_states(connection, result.instance_id)
                row = connection.execute(
                    """
                    SELECT state, command_json, command_sha256, deadline_unix,
                           enqueued_unix, result_json, result_sha256, completed_unix
                    FROM agent_commands
                    WHERE instance_id = ? AND request_id = ?
                    """,
                    (result.instance_id, result.request_id),
                ).fetchone()
                if row is None:
                    raise AgentCommandNotFoundError(
                        "Agent result does not match a queued command"
                    )
                state, _signed, cached = self._validate_row_consistency(
                    row,
                    instance_id=result.instance_id,
                    request_id=result.request_id,
                )
                if state is AgentCommandState.EXPIRED:
                    raise AgentCommandExpiredError(
                        "Agent result arrived after command expiration"
                    )
                deadline_unix = _require_finite_number(
                    row["deadline_unix"], "Agent command deadline"
                )
                if (
                    state is AgentCommandState.PENDING
                    and checked_at.timestamp() >= deadline_unix
                ):
                    connection.execute(
                        """
                        UPDATE agent_commands
                        SET state = ?
                        WHERE instance_id = ? AND request_id = ? AND state = ?
                        """,
                        (
                            AgentCommandState.EXPIRED.value,
                            result.instance_id,
                            result.request_id,
                            AgentCommandState.PENDING.value,
                        ),
                    )
                    connection.execute("COMMIT")
                    raise AgentCommandExpiredError(
                        "Agent result arrived after command expiration"
                    )
                if state is AgentCommandState.COMPLETED:
                    assert cached is not None
                    existing_hash = _require_sha256(
                        row["result_sha256"], "Agent result SHA-256"
                    )
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
                self._rollback(connection)
                raise

    def get_status(
        self,
        instance_id: str,
        request_id: str,
    ) -> AgentCommandStatus | None:
        checked_instance = _require_identifier(instance_id, "instance_id")
        checked_request = _require_identifier(request_id, "request_id")
        with self._connection() as connection:
            self._validate_instance_states(connection, checked_instance)
            row = connection.execute(
                """
                SELECT state, command_json, command_sha256, deadline_unix,
                       enqueued_unix, result_json, result_sha256, completed_unix
                FROM agent_commands
                WHERE instance_id = ? AND request_id = ?
                """,
                (checked_instance, checked_request),
            ).fetchone()
            if row is None:
                return None
            state, _signed, result = self._validate_row_consistency(
                row,
                instance_id=checked_instance,
                request_id=checked_request,
            )
            return AgentCommandStatus(
                instance_id=checked_instance,
                request_id=checked_request,
                state=state,
                result=result,
            )
