from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterator

from .agent_transport_protocol import VerifiedAgentRequest


AGENT_NONCE_RETENTION_SECONDS = 300
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_AGENT_REGISTRY_TIMEOUT_SECONDS = 30.0
_PRESENCE_COLUMNS = frozenset(
    {
        "instance_id",
        "device_id",
        "boot_id",
        "connection_epoch",
        "first_seen_unix",
        "last_seen_unix",
    }
)


class AgentConnectionRegistryError(RuntimeError):
    pass


class AgentRequestReplayError(AgentConnectionRegistryError):
    pass


class AgentStaleConnectionError(AgentConnectionRegistryError):
    pass


class AgentDeviceConflictError(AgentConnectionRegistryError):
    pass


class AgentBootConflictError(AgentConnectionRegistryError):
    pass


@dataclass(frozen=True)
class AgentPresence:
    instance_id: str
    device_id: str
    boot_id: str
    connection_epoch: int
    first_seen_at: datetime
    last_seen_at: datetime


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


class AgentConnectionRegistry:
    """Durable Bridge-side replay and connection-epoch registry.

    Callers must verify the Agent request HMAC/body/timestamp first. This store
    then atomically claims the request nonce and enforces one current device /
    boot / epoch identity per managed instance. A higher epoch supersedes the
    previous connection; lower epochs and same-epoch boot changes fail closed.

    The SQLite main database keeps lexical authority across each operation.
    Symlink/junction/reparse redirects are rejected and the pathname must retain
    the same regular-file identity while a connection is active.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds) <= _MAX_AGENT_REGISTRY_TIMEOUT_SECONDS
        ):
            raise ValueError("timeout_seconds must be finite and between 0 and 30")
        self.path = path.expanduser().absolute()
        self.timeout_seconds = float(timeout_seconds)
        self._prepare_database_authority()
        self._database_identity = self._assert_authority()
        self._initialize()

    def _assert_authority(self) -> os.stat_result:
        if _path_chain_has_redirect(self.path):
            raise AgentConnectionRegistryError(
                "Agent registry authority path traverses a link or reparse point"
            )
        if not self.path.parent.is_dir():
            raise AgentConnectionRegistryError(
                "Agent registry parent authority is not a directory"
            )
        try:
            current = self.path.stat()
        except FileNotFoundError as exc:
            raise AgentConnectionRegistryError("Agent registry database disappeared") from exc
        if not stat.S_ISREG(current.st_mode) or not self.path.is_file():
            raise AgentConnectionRegistryError(
                "Agent registry authority is not a regular file"
            )
        return current

    def _prepare_database_authority(self) -> None:
        if _path_chain_has_redirect(self.path):
            raise AgentConnectionRegistryError(
                "Agent registry authority path traverses a link or reparse point"
            )
        parent = self.path.parent
        if parent.exists() and not parent.is_dir():
            raise AgentConnectionRegistryError(
                "Agent registry parent authority is not a directory"
            )
        parent.mkdir(parents=True, exist_ok=True)
        if _path_chain_has_redirect(self.path) or not parent.is_dir():
            raise AgentConnectionRegistryError(
                "Agent registry parent authority changed during creation"
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
            raise AgentConnectionRegistryError(
                "Agent registry database identity differs from startup authority"
            )
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            after_open = self._assert_authority()
            if not _same_file_identity(before, after_open):
                raise AgentConnectionRegistryError(
                    "Agent registry authority changed during SQLite open"
                )
            yield connection
            after_use = self._assert_authority()
            if not _same_file_identity(before, after_use):
                raise AgentConnectionRegistryError(
                    "Agent registry authority changed during SQLite operation"
                )
            if not _same_file_identity(self._database_identity, after_use):
                raise AgentConnectionRegistryError(
                    "Agent registry database identity differs from startup authority"
                )
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_presence (
                    instance_id TEXT PRIMARY KEY NOT NULL,
                    device_id TEXT NOT NULL,
                    boot_id TEXT NOT NULL,
                    connection_epoch INTEGER NOT NULL,
                    first_seen_unix REAL NOT NULL,
                    last_seen_unix REAL NOT NULL
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_request_nonces (
                    device_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    seen_unix REAL NOT NULL,
                    PRIMARY KEY(device_id, nonce)
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_agent_request_nonces_seen
                ON agent_request_nonces(seen_unix)
                """
            )

    @staticmethod
    def _aware_utc(value: datetime | None) -> datetime:
        checked = value or datetime.now(timezone.utc)
        if not isinstance(checked, datetime) or checked.tzinfo is None or checked.utcoffset() is None:
            raise AgentConnectionRegistryError(
                "Agent registry timestamp must be timezone-aware"
            )
        return checked.astimezone(timezone.utc)

    @staticmethod
    def _presence_from_row(row: sqlite3.Row) -> AgentPresence:
        keys = frozenset(row.keys())
        if keys != _PRESENCE_COLUMNS:
            raise AgentConnectionRegistryError(
                "stored Agent presence columns do not match schema"
            )
        instance_id = row["instance_id"]
        device_id = row["device_id"]
        boot_id = row["boot_id"]
        connection_epoch = row["connection_epoch"]
        first_seen = row["first_seen_unix"]
        last_seen = row["last_seen_unix"]

        for label, value in (
            ("instance_id", instance_id),
            ("device_id", device_id),
            ("boot_id", boot_id),
        ):
            if not isinstance(value, str) or not value:
                raise AgentConnectionRegistryError(
                    f"stored Agent presence {label} is invalid"
                )
        if (
            isinstance(connection_epoch, bool)
            or not isinstance(connection_epoch, int)
            or connection_epoch < 1
        ):
            raise AgentConnectionRegistryError(
                "stored Agent presence connection_epoch is invalid"
            )
        for label, value in (
            ("first_seen_unix", first_seen),
            ("last_seen_unix", last_seen),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                raise AgentConnectionRegistryError(
                    f"stored Agent presence {label} is invalid"
                )

        first = datetime.fromtimestamp(float(first_seen), timezone.utc)
        last = datetime.fromtimestamp(float(last_seen), timezone.utc)
        if last < first:
            raise AgentConnectionRegistryError(
                "stored Agent presence timestamps are inconsistent"
            )
        return AgentPresence(
            instance_id=instance_id,
            device_id=device_id,
            boot_id=boot_id,
            connection_epoch=connection_epoch,
            first_seen_at=first,
            last_seen_at=last,
        )

    def accept_verified_request(
        self,
        request: VerifiedAgentRequest,
        *,
        now: datetime | None = None,
    ) -> AgentPresence:
        checked_at = self._aware_utc(now)
        seen_unix = checked_at.timestamp()
        cutoff = (
            checked_at - timedelta(seconds=AGENT_NONCE_RETENTION_SECONDS)
        ).timestamp()

        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM agent_request_nonces WHERE seen_unix < ?",
                    (cutoff,),
                )
                try:
                    connection.execute(
                        """
                        INSERT INTO agent_request_nonces(device_id, nonce, seen_unix)
                        VALUES (?, ?, ?)
                        """,
                        (request.device_id, request.nonce, seen_unix),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AgentRequestReplayError(
                        "Agent request nonce has already been used"
                    ) from exc

                row = connection.execute(
                    "SELECT * FROM agent_presence WHERE instance_id = ?",
                    (request.instance_id,),
                ).fetchone()
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO agent_presence(
                            instance_id,
                            device_id,
                            boot_id,
                            connection_epoch,
                            first_seen_unix,
                            last_seen_unix
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            request.instance_id,
                            request.device_id,
                            request.boot_id,
                            request.connection_epoch,
                            seen_unix,
                            seen_unix,
                        ),
                    )
                else:
                    current = self._presence_from_row(row)
                    if current.device_id != request.device_id:
                        raise AgentDeviceConflictError(
                            "managed instance is already bound to another Agent device"
                        )
                    if request.connection_epoch < current.connection_epoch:
                        raise AgentStaleConnectionError(
                            "Agent connection epoch is stale"
                        )
                    if (
                        request.connection_epoch == current.connection_epoch
                        and request.boot_id != current.boot_id
                    ):
                        raise AgentBootConflictError(
                            "Agent boot identity changed without a higher connection epoch"
                        )
                    if request.connection_epoch > current.connection_epoch:
                        connection.execute(
                            """
                            UPDATE agent_presence
                            SET boot_id = ?, connection_epoch = ?, last_seen_unix = ?
                            WHERE instance_id = ?
                            """,
                            (
                                request.boot_id,
                                request.connection_epoch,
                                seen_unix,
                                request.instance_id,
                            ),
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE agent_presence
                            SET last_seen_unix = ?
                            WHERE instance_id = ?
                            """,
                            (seen_unix, request.instance_id),
                        )

                accepted_row = connection.execute(
                    "SELECT * FROM agent_presence WHERE instance_id = ?",
                    (request.instance_id,),
                ).fetchone()
                if accepted_row is None:
                    raise AgentConnectionRegistryError(
                        "accepted Agent presence disappeared before commit"
                    )
                accepted = self._presence_from_row(accepted_row)
                connection.execute("COMMIT")
                return accepted
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def get_presence(self, instance_id: str) -> AgentPresence | None:
        if not isinstance(instance_id, str) or not instance_id:
            raise ValueError("instance_id is required")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM agent_presence WHERE instance_id = ?",
                (instance_id,),
            ).fetchone()
        return None if row is None else self._presence_from_row(row)
