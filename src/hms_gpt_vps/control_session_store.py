from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterable, Iterator

from .control_session import (
    ControlSessionGrant,
    ControlSessionRecord,
    ControlSessionRotation,
    revoke_control_session,
    rotate_control_session,
    verify_control_session,
)


CONTROL_SESSION_STORE_SCHEMA_VERSION = 1
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_CONTROL_SESSION_STORE_TIMEOUT_SECONDS = 30.0


class ControlSessionStoreError(RuntimeError):
    pass


class ControlSessionNotFoundError(ControlSessionStoreError):
    pass


class ControlSessionAlreadyExistsError(ControlSessionStoreError):
    pass


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


def _no_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ControlSessionStoreError(
                f"stored control session has duplicate JSON key: {key}"
            )
        result[key] = value
    return result


class ControlSessionStore:
    """Digest-only durable store for scoped control sessions.

    Rotation is atomic: `BEGIN IMMEDIATE` locks the old session record, verifies
    its token, revokes it, and inserts exactly one successor epoch before commit.
    Raw session tokens never enter SQLite.

    The main SQLite file keeps lexical authority: symlink/junction/reparse
    redirects are rejected, the database file is pre-created when absent, and
    every operation requires the same regular-file identity pinned at startup.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds) <= _MAX_CONTROL_SESSION_STORE_TIMEOUT_SECONDS
        ):
            raise ValueError("timeout_seconds must be finite and between 0 and 30")
        self.path = path.expanduser().absolute()
        self.timeout_seconds = float(timeout_seconds)
        self._prepare_database_authority()
        self._database_identity = self._assert_authority()
        self._initialize()

    def _assert_authority(self) -> os.stat_result:
        if _path_chain_has_redirect(self.path):
            raise ControlSessionStoreError(
                "control-session store authority path traverses a link or reparse point"
            )
        if not self.path.parent.is_dir():
            raise ControlSessionStoreError(
                "control-session store parent authority is not a directory"
            )
        try:
            current = self.path.stat()
        except FileNotFoundError as exc:
            raise ControlSessionStoreError(
                "control-session store database disappeared"
            ) from exc
        if not stat.S_ISREG(current.st_mode) or not self.path.is_file():
            raise ControlSessionStoreError(
                "control-session store authority is not a regular file"
            )
        return current

    def _prepare_database_authority(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise ControlSessionStoreError(
                "control-session store authority path traverses a link or reparse point"
            )
        parent = self.path.parent
        if parent.exists() and not parent.is_dir():
            raise ControlSessionStoreError(
                "control-session store parent authority is not a directory"
            )
        parent.mkdir(parents=True, exist_ok=True)
        if _path_chain_has_redirect(self.path) or not parent.is_dir():
            raise ControlSessionStoreError(
                "control-session store parent authority changed during creation"
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
            raise ControlSessionStoreError(
                "control-session store database identity differs from startup authority"
            )
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            after_open = self._assert_authority()
            if not _same_file_identity(before, after_open):
                raise ControlSessionStoreError(
                    "control-session store authority changed during SQLite open"
                )
            yield connection
            after_use = self._assert_authority()
            if not _same_file_identity(before, after_use):
                raise ControlSessionStoreError(
                    "control-session store authority changed during SQLite operation"
                )
            if not _same_file_identity(self._database_identity, after_use):
                raise ControlSessionStoreError(
                    "control-session store database identity differs from startup authority"
                )
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if isinstance(version, bool) or not isinstance(version, int):
                raise ControlSessionStoreError(
                    "control-session store schema version is not an integer"
                )
            if version not in {0, CONTROL_SESSION_STORE_SCHEMA_VERSION}:
                raise ControlSessionStoreError(
                    f"unsupported control-session store schema: {version}"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS control_sessions (
                    session_id TEXT PRIMARY KEY NOT NULL,
                    family_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    UNIQUE(family_id, epoch)
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_control_sessions_family ON control_sessions(family_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_control_sessions_instance ON control_sessions(instance_id)"
            )
            if version == 0:
                connection.execute(
                    f"PRAGMA user_version = {CONTROL_SESSION_STORE_SCHEMA_VERSION}"
                )

    @staticmethod
    def _serialize(record: ControlSessionRecord) -> str:
        record.validate()
        return json.dumps(
            record.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )

    @staticmethod
    def _deserialize(raw: object) -> ControlSessionRecord:
        if not isinstance(raw, str) or not raw:
            raise ControlSessionStoreError(
                "stored control session must be non-empty JSON text"
            )
        try:
            payload = json.loads(raw, object_pairs_hook=_no_duplicate_json_keys)
        except json.JSONDecodeError as exc:
            raise ControlSessionStoreError(
                "stored control session is invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise ControlSessionStoreError(
                "stored control session must be a JSON object"
            )
        try:
            return ControlSessionRecord.from_dict(payload)
        except ValueError as exc:
            raise ControlSessionStoreError(
                "stored control session failed validation"
            ) from exc

    @staticmethod
    def _validate_session_id(session_id: str) -> None:
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id is required")

    @staticmethod
    def _record_from_row(row: sqlite3.Row, *, expected_session_id: str) -> ControlSessionRecord:
        expected_columns = frozenset(
            {"session_id", "family_id", "instance_id", "epoch", "record_json"}
        )
        if frozenset(row.keys()) != expected_columns:
            raise ControlSessionStoreError(
                "stored control-session columns do not match schema"
            )
        session_id = row["session_id"]
        family_id = row["family_id"]
        instance_id = row["instance_id"]
        epoch = row["epoch"]
        if not isinstance(session_id, str) or not session_id:
            raise ControlSessionStoreError("stored session_id is invalid")
        if not isinstance(family_id, str) or not family_id:
            raise ControlSessionStoreError("stored session family_id is invalid")
        if not isinstance(instance_id, str) or not instance_id:
            raise ControlSessionStoreError("stored session instance_id is invalid")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise ControlSessionStoreError("stored session epoch is invalid")
        record = ControlSessionStore._deserialize(row["record_json"])
        if (
            session_id != expected_session_id
            or record.session_id != session_id
            or record.family_id != family_id
            or record.instance_id != instance_id
            or record.epoch != epoch
        ):
            raise ControlSessionStoreError("stored session identity mismatch")
        return record

    def create(self, grant: ControlSessionGrant) -> None:
        if not isinstance(grant, ControlSessionGrant):
            raise TypeError("grant must be a ControlSessionGrant")
        record = grant.record
        raw = self._serialize(record)
        try:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO control_sessions(
                        session_id, family_id, instance_id, epoch, record_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record.session_id,
                        record.family_id,
                        record.instance_id,
                        record.epoch,
                        raw,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ControlSessionAlreadyExistsError(
                f"control session already exists: {record.session_id}"
            ) from exc

    def get(self, session_id: str) -> ControlSessionRecord | None:
        self._validate_session_id(session_id)
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT session_id, family_id, instance_id, epoch, record_json
                FROM control_sessions
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return self._record_from_row(row, expected_session_id=session_id)

    def require(self, session_id: str) -> ControlSessionRecord:
        record = self.get(session_id)
        if record is None:
            raise ControlSessionNotFoundError(f"control session not found: {session_id}")
        return record

    def verify(
        self,
        session_id: str,
        token: str,
        *,
        instance_id: str,
        required_scope: str,
        now: datetime | None = None,
    ) -> ControlSessionRecord:
        record = self.require(session_id)
        verify_control_session(
            record,
            token,
            instance_id=instance_id,
            required_scope=required_scope,
            now=now,
        )
        return record

    def rotate(
        self,
        session_id: str,
        token: str,
        *,
        instance_id: str,
        now: datetime | None = None,
        ttl_seconds: int = 3600,
        scopes: Iterable[str] | None = None,
    ) -> ControlSessionRotation:
        self._validate_session_id(session_id)
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT session_id, family_id, instance_id, epoch, record_json
                    FROM control_sessions
                    WHERE session_id = ?
                    """,
                    (session_id,),
                ).fetchone()
                if row is None:
                    raise ControlSessionNotFoundError(
                        f"control session not found: {session_id}"
                    )
                current = self._record_from_row(row, expected_session_id=session_id)
                rotation = rotate_control_session(
                    current,
                    token,
                    instance_id=instance_id,
                    now=now,
                    ttl_seconds=ttl_seconds,
                    scopes=scopes,
                )
                connection.execute(
                    "UPDATE control_sessions SET record_json = ? WHERE session_id = ?",
                    (self._serialize(rotation.previous), session_id),
                )
                successor = rotation.grant.record
                connection.execute(
                    """
                    INSERT INTO control_sessions(
                        session_id, family_id, instance_id, epoch, record_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        successor.session_id,
                        successor.family_id,
                        successor.instance_id,
                        successor.epoch,
                        self._serialize(successor),
                    ),
                )
                connection.execute("COMMIT")
                return rotation
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def revoke(
        self,
        session_id: str,
        *,
        reason: str = "revoked",
        now: datetime | None = None,
    ) -> ControlSessionRecord:
        self._validate_session_id(session_id)
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT session_id, family_id, instance_id, epoch, record_json
                    FROM control_sessions
                    WHERE session_id = ?
                    """,
                    (session_id,),
                ).fetchone()
                if row is None:
                    raise ControlSessionNotFoundError(
                        f"control session not found: {session_id}"
                    )
                current = self._record_from_row(row, expected_session_id=session_id)
                revoked = revoke_control_session(current, reason=reason, now=now)
                connection.execute(
                    "UPDATE control_sessions SET record_json = ? WHERE session_id = ?",
                    (self._serialize(revoked), session_id),
                )
                connection.execute("COMMIT")
                return revoked
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
