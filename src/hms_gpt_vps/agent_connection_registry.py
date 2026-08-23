from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

from .agent_transport_protocol import VerifiedAgentRequest


AGENT_NONCE_RETENTION_SECONDS = 300


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


class AgentConnectionRegistry:
    """Durable Bridge-side replay and connection-epoch registry.

    Callers must verify the Agent request HMAC/body/timestamp first. This store
    then atomically claims the request nonce and enforces one current device /
    boot / epoch identity per managed instance. A higher epoch supersedes the
    previous connection; lower epochs and same-epoch boot changes fail closed.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        self.path = path
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
        if checked.tzinfo is None or checked.utcoffset() is None:
            raise AgentConnectionRegistryError(
                "Agent registry timestamp must be timezone-aware"
            )
        return checked.astimezone(timezone.utc)

    @staticmethod
    def _presence_from_row(row: sqlite3.Row) -> AgentPresence:
        return AgentPresence(
            instance_id=str(row["instance_id"]),
            device_id=str(row["device_id"]),
            boot_id=str(row["boot_id"]),
            connection_epoch=int(row["connection_epoch"]),
            first_seen_at=datetime.fromtimestamp(
                float(row["first_seen_unix"]), timezone.utc
            ),
            last_seen_at=datetime.fromtimestamp(
                float(row["last_seen_unix"]), timezone.utc
            ),
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

        connection = self._connect()
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
            assert accepted_row is not None
            accepted = self._presence_from_row(accepted_row)
            connection.execute("COMMIT")
            return accepted
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def get_presence(self, instance_id: str) -> AgentPresence | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM agent_presence WHERE instance_id = ?",
                (instance_id,),
            ).fetchone()
        return None if row is None else self._presence_from_row(row)
