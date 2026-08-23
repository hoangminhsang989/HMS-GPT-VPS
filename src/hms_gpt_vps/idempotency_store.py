from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping


IDEMPOTENCY_STORE_SCHEMA_VERSION = 1
MAX_IDEMPOTENCY_RESPONSE_BYTES = 1024 * 1024


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
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("idempotency timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_identifier(value: str, name: str) -> None:
    if not value or len(value) > 128:
        raise ValueError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise ValueError(f"{name} contains unsupported characters")


def _validate_sha256(value: str, name: str) -> None:
    if len(value) != 64:
        raise ValueError(f"{name} must contain 64 hex characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc


def _response_json(response: Mapping[str, Any]) -> tuple[str, str]:
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


class IdempotencyStore:
    """Fail-closed replay protection for authenticated control requests.

    A newly accepted request is persisted as CLAIMED before any side effect.
    If the Bridge crashes before COMPLETED is written, later retries receive an
    ambiguity error and are not re-executed automatically. Request bodies and
    authentication tokens are not stored; only the canonical request SHA-256 is.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = path.expanduser().resolve()
        self.timeout_seconds = timeout_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
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

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_sha256, state, response_json, response_sha256
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
                        request_sha256.lower(),
                        IdempotencyState.CLAIMED.value,
                        claimed_at,
                    ),
                )
                connection.execute("COMMIT")
                return IdempotencyClaim(is_new=True)

            if str(row["request_sha256"]).lower() != request_sha256.lower():
                raise IdempotencyConflictError(
                    "idempotency key was already used for a different request"
                )
            state = str(row["state"])
            if state == IdempotencyState.CLAIMED.value:
                raise IdempotencyInProgressError(
                    "request has an unresolved prior claim; automatic replay is blocked"
                )
            if state != IdempotencyState.COMPLETED.value:
                raise IdempotencyError(f"unsupported idempotency state: {state}")

            response_json = row["response_json"]
            response_sha256 = row["response_sha256"]
            if not isinstance(response_json, str) or not isinstance(response_sha256, str):
                raise IdempotencyError("completed idempotency record is incomplete")
            raw = response_json.encode("utf-8")
            if hashlib.sha256(raw).hexdigest() != response_sha256.lower():
                raise IdempotencyError("cached idempotency response failed integrity check")
            payload = json.loads(response_json)
            if not isinstance(payload, dict):
                raise IdempotencyError("cached idempotency response must be an object")
            connection.execute("COMMIT")
            return IdempotencyClaim(is_new=False, replay_response=payload)
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

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_sha256, state, response_json, response_sha256
                FROM idempotency_records
                WHERE session_id = ? AND request_id = ?
                """,
                (session_id, request_id),
            ).fetchone()
            if row is None:
                raise IdempotencyNotFoundError("idempotency claim does not exist")
            if str(row["request_sha256"]).lower() != request_sha256.lower():
                raise IdempotencyConflictError(
                    "idempotency request hash does not match existing claim"
                )

            state = str(row["state"])
            if state == IdempotencyState.COMPLETED.value:
                existing_hash = row["response_sha256"]
                if not isinstance(existing_hash, str) or existing_hash.lower() != response_sha256:
                    raise IdempotencyConflictError(
                        "completed idempotency result differs from supplied result"
                    )
                existing_json = row["response_json"]
                if not isinstance(existing_json, str):
                    raise IdempotencyError("completed idempotency record is incomplete")
                payload = json.loads(existing_json)
                if not isinstance(payload, dict):
                    raise IdempotencyError("cached idempotency response must be an object")
                connection.execute("COMMIT")
                return payload
            if state != IdempotencyState.CLAIMED.value:
                raise IdempotencyError(f"unsupported idempotency state: {state}")

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
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
