from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterator

from .pairing import (
    PairingRecord,
    consume_pairing_record,
    revoke_pairing_record,
)


PAIRING_STORE_SCHEMA_VERSION = 1
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_PAIRING_STORE_TIMEOUT_SECONDS = 30.0


class PairingStoreError(RuntimeError):
    pass


class PairingNotFoundError(PairingStoreError):
    pass


class PairingAlreadyExistsError(PairingStoreError):
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
            raise PairingStoreError(f"stored pairing record has duplicate JSON key: {key}")
        result[key] = value
    return result


class PairingStore:
    """Durable digest-only store for short-lived one-time pairing grants.

    Raw pairing tokens never enter SQLite. Consume/revoke operations use
    `BEGIN IMMEDIATE` so concurrent requests serialize before the record is
    verified and mutated; therefore one token cannot be consumed twice.

    The main SQLite file keeps lexical authority: symlink/junction/reparse
    redirects are rejected, the database file is pre-created when absent, and
    each connection verifies that the pathname still names the same regular-file
    identity for the entire operation.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds) <= _MAX_PAIRING_STORE_TIMEOUT_SECONDS
        ):
            raise ValueError("timeout_seconds must be finite and between 0 and 30")
        self.path = path.expanduser().absolute()
        self.timeout_seconds = float(timeout_seconds)
        self._prepare_database_authority()
        self._database_identity = self._assert_authority()
        self._initialize()

    def _assert_authority(self) -> os.stat_result:
        if _path_chain_has_redirect(self.path):
            raise PairingStoreError(
                "pairing-store authority path traverses a link or reparse point"
            )
        if not self.path.parent.is_dir():
            raise PairingStoreError("pairing-store parent authority is not a directory")
        try:
            current = self.path.stat()
        except FileNotFoundError as exc:
            raise PairingStoreError("pairing-store database disappeared") from exc
        if not stat.S_ISREG(current.st_mode) or not self.path.is_file():
            raise PairingStoreError("pairing-store authority is not a regular file")
        return current

    def _prepare_database_authority(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise PairingStoreError(
                "pairing-store authority path traverses a link or reparse point"
            )
        parent = self.path.parent
        if parent.exists() and not parent.is_dir():
            raise PairingStoreError("pairing-store parent authority is not a directory")
        parent.mkdir(parents=True, exist_ok=True)
        if _path_chain_has_redirect(self.path) or not parent.is_dir():
            raise PairingStoreError("pairing-store parent authority changed during creation")

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
            raise PairingStoreError("pairing-store database identity differs from startup authority")
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            after_open = self._assert_authority()
            if not _same_file_identity(before, after_open):
                raise PairingStoreError("pairing-store authority changed during SQLite open")
            yield connection
            after_use = self._assert_authority()
            if not _same_file_identity(before, after_use):
                raise PairingStoreError("pairing-store authority changed during SQLite operation")
            if not _same_file_identity(self._database_identity, after_use):
                raise PairingStoreError("pairing-store database identity differs from startup authority")
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            current_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if isinstance(current_version, bool) or not isinstance(current_version, int):
                raise PairingStoreError("pairing-store schema version is not an integer")
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
            allow_nan=False,
        )

    @staticmethod
    def _deserialize(raw: object) -> PairingRecord:
        if not isinstance(raw, str) or not raw:
            raise PairingStoreError("stored pairing record must be non-empty JSON text")
        try:
            payload = json.loads(raw, object_pairs_hook=_no_duplicate_json_keys)
        except json.JSONDecodeError as exc:
            raise PairingStoreError("stored pairing record is invalid JSON") from exc
        if not isinstance(payload, dict):
            raise PairingStoreError("stored pairing record must be a JSON object")
        try:
            return PairingRecord.from_dict(payload)
        except ValueError as exc:
            raise PairingStoreError("stored pairing record failed validation") from exc

    @staticmethod
    def _validate_pair_id(pair_id: str) -> None:
        if not isinstance(pair_id, str) or not pair_id:
            raise ValueError("pair_id is required")

    def create(self, record: PairingRecord) -> None:
        raw = self._serialize(record)
        try:
            with self._connection() as connection:
                connection.execute(
                    "INSERT INTO pairing_records(pair_id, instance_id, record_json) VALUES (?, ?, ?)",
                    (record.pair_id, record.instance_id, raw),
                )
        except sqlite3.IntegrityError as exc:
            raise PairingAlreadyExistsError(
                f"pairing record already exists: {record.pair_id}"
            ) from exc

    def get(self, pair_id: str) -> PairingRecord | None:
        self._validate_pair_id(pair_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT instance_id, record_json FROM pairing_records WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
        if row is None:
            return None
        instance_id = row["instance_id"]
        if not isinstance(instance_id, str) or not instance_id:
            raise PairingStoreError("stored pairing instance_id is invalid")
        record = self._deserialize(row["record_json"])
        if record.pair_id != pair_id or record.instance_id != instance_id:
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
        self._validate_pair_id(pair_id)
        if not isinstance(instance_id, str) or not instance_id:
            raise ValueError("instance_id is required")
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT instance_id, record_json FROM pairing_records WHERE pair_id = ?",
                    (pair_id,),
                ).fetchone()
                if row is None:
                    raise PairingNotFoundError(f"pairing record not found: {pair_id}")
                stored_instance = row["instance_id"]
                if not isinstance(stored_instance, str) or not stored_instance:
                    raise PairingStoreError("stored pairing instance_id is invalid")
                record = self._deserialize(row["record_json"])
                if record.pair_id != pair_id or record.instance_id != stored_instance:
                    raise PairingStoreError("stored pairing identity mismatch")
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

    def revoke(
        self,
        pair_id: str,
        *,
        now: datetime | None = None,
    ) -> PairingRecord:
        self._validate_pair_id(pair_id)
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT instance_id, record_json FROM pairing_records WHERE pair_id = ?",
                    (pair_id,),
                ).fetchone()
                if row is None:
                    raise PairingNotFoundError(f"pairing record not found: {pair_id}")
                stored_instance = row["instance_id"]
                if not isinstance(stored_instance, str) or not stored_instance:
                    raise PairingStoreError("stored pairing instance_id is invalid")
                record = self._deserialize(row["record_json"])
                if record.pair_id != pair_id or record.instance_id != stored_instance:
                    raise PairingStoreError("stored pairing identity mismatch")
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
