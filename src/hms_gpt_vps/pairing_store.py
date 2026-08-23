from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import sqlite3

from .pairing import (
    PairingRecord,
    consume_pairing_record,
    revoke_pairing_record,
)


PAIRING_STORE_SCHEMA_VERSION = 1


class PairingStoreError(RuntimeError):
    pass


class PairingNotFoundError(PairingStoreError):
    pass


class PairingAlreadyExistsError(PairingStoreError):
    pass


class PairingStore:
    """Durable digest-only store for short-lived one-time pairing grants.

    Raw pairing tokens never enter SQLite. Consume/revoke operations use
    `BEGIN IMMEDIATE` so concurrent requests serialize before the record is
    verified and mutated; therefore one token cannot be consumed twice.
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
            current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_version not in {0, PAIRING_STORE_SCHEMA_VERSION}:
                raise PairingStoreError(
                    f"unsupported pairing-store schema: {current_version}"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pairing_records (
                    pair_id TEXT PRIMARY KEY NOT NULL,
                    instance_id TEXT NOT NULL,
                    record_json TEXT NOT NULL
                ) WITHOUT ROWID
                """
            )
            if current_version == 0:
                connection.execute(f"PRAGMA user_version = {PAIRING_STORE_SCHEMA_VERSION}")

    @staticmethod
    def _serialize(record: PairingRecord) -> str:
        record.validate()
        return json.dumps(
            record.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _deserialize(raw: str) -> PairingRecord:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PairingStoreError("stored pairing record is invalid JSON") from exc
        if not isinstance(payload, dict):
            raise PairingStoreError("stored pairing record must be a JSON object")
        try:
            return PairingRecord.from_dict(payload)
        except ValueError as exc:
            raise PairingStoreError("stored pairing record failed validation") from exc

    def create(self, record: PairingRecord) -> None:
        raw = self._serialize(record)
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO pairing_records(pair_id, instance_id, record_json) VALUES (?, ?, ?)",
                    (record.pair_id, record.instance_id, raw),
                )
        except sqlite3.IntegrityError as exc:
            raise PairingAlreadyExistsError(
                f"pairing record already exists: {record.pair_id}"
            ) from exc

    def get(self, pair_id: str) -> PairingRecord | None:
        if not pair_id:
            raise ValueError("pair_id is required")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM pairing_records WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
        if row is None:
            return None
        record = self._deserialize(str(row["record_json"]))
        if record.pair_id != pair_id:
            raise PairingStoreError("stored pairing identity mismatch")
        return record

    def require(self, pair_id: str) -> PairingRecord:
        record = self.get(pair_id)
        if record is None:
            raise PairingNotFoundError(f"pairing record not found: {pair_id}")
        return record

    def consume(
        self,
        pair_id: str,
        token: str,
        *,
        instance_id: str,
        now: datetime | None = None,
    ) -> PairingRecord:
        """Atomically verify and consume one pairing grant exactly once."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT instance_id, record_json FROM pairing_records WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
            if row is None:
                raise PairingNotFoundError(f"pairing record not found: {pair_id}")
            if str(row["instance_id"]) != instance_id:
                # Keep public behavior indistinguishable from token/instance
                # verification performed by the pairing contract.
                record = self._deserialize(str(row["record_json"]))
                consumed = consume_pairing_record(
                    record,
                    token,
                    instance_id=instance_id,
                    now=now,
                )
            else:
                record = self._deserialize(str(row["record_json"]))
                consumed = consume_pairing_record(
                    record,
                    token,
                    instance_id=instance_id,
                    now=now,
                )
            connection.execute(
                "UPDATE pairing_records SET record_json = ? WHERE pair_id = ?",
                (self._serialize(consumed), pair_id),
            )
            connection.execute("COMMIT")
            return consumed
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
        pair_id: str,
        *,
        now: datetime | None = None,
    ) -> PairingRecord:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT record_json FROM pairing_records WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
            if row is None:
                raise PairingNotFoundError(f"pairing record not found: {pair_id}")
            record = self._deserialize(str(row["record_json"]))
            revoked = revoke_pairing_record(record, now=now)
            connection.execute(
                "UPDATE pairing_records SET record_json = ? WHERE pair_id = ?",
                (self._serialize(revoked), pair_id),
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
