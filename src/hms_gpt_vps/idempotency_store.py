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
from typing import Any, Iterator, Mapping


IDEMPOTENCY_STORE_SCHEMA_VERSION = 1
MAX_IDEMPOTENCY_RESPONSE_BYTES = 1024 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_IDEMPOTENCY_STORE_TIMEOUT_SECONDS = 30.0
_HEX_LOWER = frozenset("0123456789abcdef")


class IdempotencyState(str, Enum):
    CLAIMED = "claimed"
    COMPLETED = "completed"


class IdempotencyError(RuntimeError):
    pass


class IdempotencyConflictError(IdempotencyError):
    pass


class IdempotencyInProgressError(IdempotencyError):
    pass


class IdempotencyNotFoundError(IdempotencyError):
    pass


@dataclass(frozen=True)
class IdempotencyClaim:
    is_new: bool
    replay_response: dict[str, Any] | None = None


def _utc_iso(now: datetime | None = None) -> str:
    value = now or datetime.now(timezone.utc)
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("idempotency timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise ValueError(f"{name} contains unsupported characters")


def _validate_sha256(value: str, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in _HEX_LOWER for char in value)
    ):
        raise ValueError(f"{name} must be canonical lowercase SHA-256")


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
            raise IdempotencyError(
                f"cached idempotency response has duplicate JSON key: {key}"
            )
        result[key] = value
    return result


def _strict_response_object(raw_text: object) -> dict[str, Any]:
    if not isinstance(raw_text, str):
        raise IdempotencyError(
            "cached idempotency response must be JSON text"
        )
    encoded = raw_text.encode("utf-8")
    if not encoded or len(encoded) > MAX_IDEMPOTENCY_RESPONSE_BYTES:
        raise IdempotencyError(
            "cached idempotency response size is invalid"
        )
    try:
        payload = json.loads(
            raw_text,
            object_pairs_hook=_no_duplicate_json_keys,
        )
    except json.JSONDecodeError as exc:
        raise IdempotencyError(
            "cached idempotency response is invalid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise IdempotencyError(
            "cached idempotency response must be an object"
        )
    return payload


def _response_json(response: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(response, Mapping):
        raise ValueError("idempotency response must be an object")
    try:
        raw = json.dumps(
            dict(response),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("idempotency response must be JSON-safe") from exc
    if len(raw) > MAX_IDEMPOTENCY_RESPONSE_BYTES:
        raise ValueError("idempotency response exceeds maximum size")
    return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise IdempotencyError(f"stored {name} must be a non-empty string")
    return value


def _require_sha256(value: object, name: str) -> str:
    digest = _require_text(value, name)
    try:
        _validate_sha256(digest, name)
    except ValueError as exc:
        raise IdempotencyError(str(exc)) from exc
    return digest


def _require_state(value: object) -> IdempotencyState:
    state_text = _require_text(value, "idempotency state")
    try:
        return IdempotencyState(state_text)
    except ValueError as exc:
        raise IdempotencyError(
            f"unsupported idempotency state: {state_text}"
        ) from exc


def _require_canonical_timestamp(value: object, name: str) -> datetime:
    text = _require_text(value, name)
    if not text.endswith("Z"):
        raise IdempotencyError(
            f"stored {name} must be a canonical UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise IdempotencyError(
            f"stored {name} is not a valid timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IdempotencyError(
            f"stored {name} must be timezone-aware"
        )
    parsed = parsed.astimezone(timezone.utc)
    if _utc_iso(parsed) != text:
        raise IdempotencyError(
            f"stored {name} must be a canonical UTC timestamp"
        )
    return parsed


def _verified_response(
    response_json: object,
    response_sha256: object,
) -> dict[str, Any]:
    raw_text = _require_text(response_json, "idempotency response JSON")
    digest = _require_sha256(
        response_sha256,
        "idempotency response SHA-256",
    )
    if hashlib.sha256(raw_text.encode("utf-8")).hexdigest() != digest:
        raise IdempotencyError(
            "cached idempotency response failed integrity check"
        )
    return _strict_response_object(raw_text)


class IdempotencyStore:
    """Fail-closed replay protection for authenticated control requests.

    A newly accepted request is persisted as CLAIMED before any side effect.
    If the Bridge crashes before COMPLETED is written, later retries receive an
    ambiguity error and are not re-executed automatically. Request bodies and
    authentication tokens are not stored; only the canonical request SHA-256 is.

    The SQLite database path is lexical authority. Redirects are rejected and
    every operation must preserve the regular-file identity pinned at startup.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds)
            <= _MAX_IDEMPOTENCY_STORE_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "timeout_seconds must be finite and between 0 and 30"
            )
        self.path = path.expanduser().absolute()
        self.timeout_seconds = float(timeout_seconds)
        self._prepare_database_authority()
        self._database_identity = self._assert_authority()
        self._initialize()

    def _assert_authority(self) -> os.stat_result:
        if _path_chain_has_redirect(self.path):
            raise IdempotencyError(
                "idempotency store authority path traverses a link or reparse point"
            )
        if not self.path.parent.is_dir():
            raise IdempotencyError(
                "idempotency store parent authority is not a directory"
            )
        try:
            current = self.path.stat()
        except FileNotFoundError as exc:
            raise IdempotencyError(
                "idempotency store database disappeared"
            ) from exc
        if not stat.S_ISREG(current.st_mode) or not self.path.is_file():
            raise IdempotencyError(
                "idempotency store authority is not a regular file"
            )
        return current

    def _prepare_database_authority(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise IdempotencyError(
                "idempotency store authority path traverses a link or reparse point"
            )
        parent = self.path.parent
        if parent.exists() and not parent.is_dir():
            raise IdempotencyError(
                "idempotency store parent authority is not a directory"
            )
        parent.mkdir(parents=True, exist_ok=True)
        if _path_chain_has_redirect(self.path) or not parent.is_dir():
            raise IdempotencyError(
                "idempotency store parent authority changed during creation"
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
            raise IdempotencyError(
                "idempotency store database identity differs from startup authority"
            )
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            after_open = self._assert_authority()
            if not _same_file_identity(before, after_open):
                raise IdempotencyError(
                    "idempotency store authority changed during SQLite open"
                )
            yield connection
            after_use = self._assert_authority()
            if not _same_file_identity(before, after_use):
                raise IdempotencyError(
                    "idempotency store authority changed during SQLite operation"
                )
            if not _same_file_identity(self._database_identity, after_use):
                raise IdempotencyError(
                    "idempotency store database identity differs from startup authority"
                )
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if isinstance(version, bool) or not isinstance(version, int):
                raise IdempotencyError(
                    "idempotency-store schema version is not an integer"
                )
            if version not in {0, IDEMPOTENCY_STORE_SCHEMA_VERSION}:
                raise IdempotencyError(
                    f"unsupported idempotency-store schema: {version}"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_records (
                    session_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    response_json TEXT,
                    response_sha256 TEXT,
                    claimed_at TEXT NOT NULL,
                    completed_at TEXT,
                    PRIMARY KEY(session_id, request_id)
                ) WITHOUT ROWID
                """
            )
            if version == 0:
                connection.execute(
                    f"PRAGMA user_version = {IDEMPOTENCY_STORE_SCHEMA_VERSION}"
                )

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    @staticmethod
    def _validate_row(
        row: sqlite3.Row,
        *,
        expected_request_sha256: str,
    ) -> tuple[IdempotencyState, dict[str, Any] | None]:
        required = {
            "request_sha256",
            "state",
            "response_json",
            "response_sha256",
            "claimed_at",
            "completed_at",
        }
        if set(row.keys()) != required:
            raise IdempotencyError(
                "stored idempotency row fields do not match authority schema"
            )
        stored_request_sha256 = _require_sha256(
            row["request_sha256"],
            "request_sha256",
        )
        if stored_request_sha256 != expected_request_sha256:
            raise IdempotencyConflictError(
                "idempotency key was already used for a different request"
            )
        state = _require_state(row["state"])
        claimed_at = _require_canonical_timestamp(
            row["claimed_at"],
            "idempotency claimed_at",
        )

        if state is IdempotencyState.CLAIMED:
            if (
                row["response_json"] is not None
                or row["response_sha256"] is not None
                or row["completed_at"] is not None
            ):
                raise IdempotencyError(
                    "claimed idempotency record contains completed-response authority"
                )
            return state, None

        completed_at = _require_canonical_timestamp(
            row["completed_at"],
            "idempotency completed_at",
        )
        if completed_at < claimed_at:
            raise IdempotencyError(
                "idempotency completion precedes claim"
            )
        return state, _verified_response(
            row["response_json"],
            row["response_sha256"],
        )

    def claim(
        self,
        session_id: str,
        request_id: str,
        request_sha256: str,
        *,
        now: datetime | None = None,
    ) -> IdempotencyClaim:
        _validate_identifier(session_id, "session_id")
        _validate_identifier(request_id, "request_id")
        _validate_sha256(request_sha256, "request_sha256")
        claimed_at = _utc_iso(now)

        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT request_sha256, state, response_json, response_sha256,
                           claimed_at, completed_at
                    FROM idempotency_records
                    WHERE session_id = ? AND request_id = ?
                    """,
                    (session_id, request_id),
                ).fetchone()
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO idempotency_records(
                            session_id, request_id, request_sha256, state, claimed_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            session_id,
                            request_id,
                            request_sha256,
                            IdempotencyState.CLAIMED.value,
                            claimed_at,
                        ),
                    )
                    connection.execute("COMMIT")
                    return IdempotencyClaim(is_new=True)

                state, replay = self._validate_row(
                    row,
                    expected_request_sha256=request_sha256,
                )
                if state is IdempotencyState.CLAIMED:
                    raise IdempotencyInProgressError(
                        "request has an unresolved prior claim; automatic replay is blocked"
                    )
                assert replay is not None
                connection.execute("COMMIT")
                return IdempotencyClaim(
                    is_new=False,
                    replay_response=replay,
                )
            except Exception:
                self._rollback(connection)
                raise

    def complete(
        self,
        session_id: str,
        request_id: str,
        request_sha256: str,
        response: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        _validate_identifier(session_id, "session_id")
        _validate_identifier(request_id, "request_id")
        _validate_sha256(request_sha256, "request_sha256")
        response_json, response_sha256 = _response_json(response)
        completed_at = _utc_iso(now)

        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT request_sha256, state, response_json, response_sha256,
                           claimed_at, completed_at
                    FROM idempotency_records
                    WHERE session_id = ? AND request_id = ?
                    """,
                    (session_id, request_id),
                ).fetchone()
                if row is None:
                    raise IdempotencyNotFoundError(
                        "idempotency claim does not exist"
                    )

                state, replay = self._validate_row(
                    row,
                    expected_request_sha256=request_sha256,
                )
                if state is IdempotencyState.COMPLETED:
                    assert replay is not None
                    existing_hash = _require_sha256(
                        row["response_sha256"],
                        "idempotency response SHA-256",
                    )
                    if existing_hash != response_sha256:
                        raise IdempotencyConflictError(
                            "completed idempotency result differs from supplied result"
                        )
                    connection.execute("COMMIT")
                    return replay

                claimed_at = _require_canonical_timestamp(
                    row["claimed_at"],
                    "idempotency claimed_at",
                )
                completed_dt = _require_canonical_timestamp(
                    completed_at,
                    "idempotency completed_at",
                )
                if completed_dt < claimed_at:
                    raise IdempotencyError(
                        "idempotency completion precedes claim"
                    )

                connection.execute(
                    """
                    UPDATE idempotency_records
                    SET state = ?, response_json = ?, response_sha256 = ?, completed_at = ?
                    WHERE session_id = ? AND request_id = ?
                    """,
                    (
                        IdempotencyState.COMPLETED.value,
                        response_json,
                        response_sha256,
                        completed_at,
                        session_id,
                        request_id,
                    ),
                )
                connection.execute("COMMIT")
                return dict(response)
            except Exception:
                self._rollback(connection)
                raise
