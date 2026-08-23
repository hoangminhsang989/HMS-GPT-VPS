from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3


_MAX_SQLITE_EPOCH = (1 << 63) - 1
_SAFE_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


class AgentConnectionEpochError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentConnectionEpochRecord:
    instance_id: str
    device_id: str
    epoch: int

    def validate(self) -> None:
        _validate_identifier(self.instance_id, "instance_id")
        _validate_identifier(self.device_id, "device_id")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool):
            raise AgentConnectionEpochError("epoch must be an integer")
        if not 1 <= self.epoch <= _MAX_SQLITE_EPOCH:
            raise AgentConnectionEpochError("epoch is outside supported bounds")


def _validate_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise AgentConnectionEpochError(f"{name} is invalid")
    if any(char not in _SAFE_IDENTIFIER_CHARS for char in value):
        raise AgentConnectionEpochError(f"{name} contains unsupported characters")


class AgentConnectionEpochStore:
    """SQLite monotonic epoch allocator for one guest Agent device identity."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_connection_epoch (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                instance_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                epoch INTEGER NOT NULL CHECK (epoch >= 1)
            )
            """
        )
        return connection

    def load(self) -> AgentConnectionEpochRecord | None:
        if not self.path.exists():
            return None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT instance_id, device_id, epoch FROM agent_connection_epoch WHERE singleton = 1"
            ).fetchone()
        if row is None:
            return None
        record = AgentConnectionEpochRecord(
            instance_id=str(row[0]),
            device_id=str(row[1]),
            epoch=int(row[2]),
        )
        record.validate()
        return record

    def allocate_next(self, *, instance_id: str, device_id: str) -> AgentConnectionEpochRecord:
        _validate_identifier(instance_id, "instance_id")
        _validate_identifier(device_id, "device_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT instance_id, device_id, epoch FROM agent_connection_epoch WHERE singleton = 1"
            ).fetchone()
            if row is None:
                epoch = 1
                connection.execute(
                    "INSERT INTO agent_connection_epoch(singleton, instance_id, device_id, epoch) VALUES (1, ?, ?, ?)",
                    (instance_id, device_id, epoch),
                )
            else:
                stored_instance = str(row[0])
                stored_device = str(row[1])
                stored_epoch = int(row[2])
                if stored_instance != instance_id:
                    raise AgentConnectionEpochError(
                        "connection epoch store belongs to another instance"
                    )
                if stored_device != device_id:
                    raise AgentConnectionEpochError(
                        "connection epoch store belongs to another device"
                    )
                if not 1 <= stored_epoch < _MAX_SQLITE_EPOCH:
                    raise AgentConnectionEpochError("connection epoch is exhausted or corrupt")
                epoch = stored_epoch + 1
                connection.execute(
                    "UPDATE agent_connection_epoch SET epoch = ? WHERE singleton = 1",
                    (epoch,),
                )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

        record = AgentConnectionEpochRecord(
            instance_id=instance_id,
            device_id=device_id,
            epoch=epoch,
        )
        record.validate()
        return record
