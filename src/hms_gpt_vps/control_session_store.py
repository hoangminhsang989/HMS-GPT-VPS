from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import sqlite3
from typing import Iterable

from .control_session import (
    ControlSessionGrant,
    ControlSessionRecord,
    ControlSessionRotation,
    revoke_control_session,
    rotate_control_session,
    verify_control_session,
)


CONTROL_SESSION_STORE_SCHEMA_VERSION = 1


class ControlSessionStoreError(RuntimeError):
    pass


class ControlSessionNotFoundError(ControlSessionStoreError):
    pass


class ControlSessionAlreadyExistsError(ControlSessionStoreError):
    pass


class ControlSessionStore:
    """Digest-only durable store for scoped control sessions.

    Rotation is atomic: `BEGIN IMMEDIATE` locks the old session record, verifies
    its token, revokes it, and inserts exactly one successor epoch before commit.
    Raw session tokens never enter SQLite.
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
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
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
        )

    @staticmethod
    def _deserialize(raw: str) -> ControlSessionRecord:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ControlSessionStoreError("stored control session is invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ControlSessionStoreError("stored control session must be a JSON object")
        try:
            return ControlSessionRecord.from_dict(payload)
        except ValueError as exc:
            raise ControlSessionStoreError("stored control session failed validation") from exc

    def create(self, grant: ControlSessionGrant) -> None:
        record = grant.record
        raw = self._serialize(record)
        try:
            with self._connect() as connection:
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
        if not session_id:
            raise ValueError("session_id is required")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM control_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        record = self._deserialize(str(row["record_json"]))
        if record.session_id != session_id:
            raise ControlSessionStoreError("stored session identity mismatch")
        return record

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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT record_json FROM control_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row is None:
                raise ControlSessionNotFoundError(
                    f"control session not found: {session_id}"
                )
            current = self._deserialize(str(row["record_json"]))
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
        finally:
            connection.close()

    def revoke(
        self,
        session_id: str,
        *,
        reason: str = "revoked",
        now: datetime | None = None,
    ) -> ControlSessionRecord:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT record_json FROM control_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row is None:
                raise ControlSessionNotFoundError(
                    f"control session not found: {session_id}"
                )
            current = self._deserialize(str(row["record_json"]))
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
        finally:
            connection.close()
