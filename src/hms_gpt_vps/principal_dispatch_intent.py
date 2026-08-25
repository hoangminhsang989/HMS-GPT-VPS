from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .idempotency_store import (
    IdempotencyError,
    IdempotencyState,
    IdempotencyStore,
    _utc_iso,
)


PRINCIPAL_DISPATCH_INTENT_SCHEMA_VERSION = 1
_HEX_LOWER = frozenset("0123456789abcdef")
_DISPATCH_ROW_FIELDS = {
    "schema_version",
    "principal_sha256",
    "pair_id",
    "session_id",
    "session_epoch",
    "instance_id",
    "request_id",
    "request_sha256",
    "command_sha256",
    "expires_at",
}


class PrincipalDispatchIntentError(RuntimeError):
    pass


class PrincipalDispatchIntentConflictError(PrincipalDispatchIntentError):
    pass


class PrincipalDispatchIntentAmbiguousError(PrincipalDispatchIntentError):
    pass


class PrincipalDispatchClaimState(str, Enum):
    NEW = "new"
    RESUME = "resume"
    REPLAY = "replay"


@dataclass(frozen=True)
class PrincipalDispatchClaim:
    state: PrincipalDispatchClaimState
    replay_response: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, PrincipalDispatchClaimState):
            raise PrincipalDispatchIntentError(
                "dispatch claim state is invalid"
            )
        if self.state is PrincipalDispatchClaimState.REPLAY:
            if not isinstance(self.replay_response, dict):
                raise PrincipalDispatchIntentError(
                    "replay dispatch claim requires a cached response"
                )
        elif self.replay_response is not None:
            raise PrincipalDispatchIntentError(
                "non-replay dispatch claim must not contain a response"
            )


def _canonical_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in _HEX_LOWER for char in value)
    ):
        raise PrincipalDispatchIntentError(
            f"{name} must be canonical lowercase SHA-256"
        )
    return value


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise PrincipalDispatchIntentError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise PrincipalDispatchIntentError(
            f"{name} contains unsupported characters"
        )
    return value


def _instance_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 128
    ):
        raise PrincipalDispatchIntentError("instance_id is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PrincipalDispatchIntentError(
            "instance_id contains control characters"
        )
    return value


def _aware_utc(value: datetime, name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise PrincipalDispatchIntentError(
            f"{name} must be timezone-aware"
        )
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware_utc(value, "expires_at").isoformat().replace(
        "+00:00",
        "Z",
    )


def _parse_iso(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise PrincipalDispatchIntentError(
            "expires_at must be a timestamp string"
        )
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PrincipalDispatchIntentError(
            "expires_at is not a valid timestamp"
        ) from exc
    parsed = _aware_utc(parsed, "expires_at")
    if _iso(parsed) != value:
        raise PrincipalDispatchIntentError(
            "expires_at must be canonical UTC"
        )
    return parsed


@dataclass(frozen=True)
class PrincipalDispatchIntent:
    schema_version: int
    principal_sha256: str
    pair_id: str
    session_id: str
    session_epoch: int
    instance_id: str
    request_id: str
    request_sha256: str
    command_sha256: str
    expires_at: datetime

    def validate(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != PRINCIPAL_DISPATCH_INTENT_SCHEMA_VERSION
        ):
            raise PrincipalDispatchIntentError(
                "unsupported dispatch intent schema"
            )
        _canonical_sha256(self.principal_sha256, "principal_sha256")
        _identifier(self.pair_id, "pair_id")
        _identifier(self.session_id, "session_id")
        if (
            isinstance(self.session_epoch, bool)
            or not isinstance(self.session_epoch, int)
            or self.session_epoch < 1
        ):
            raise PrincipalDispatchIntentError(
                "session_epoch must be a positive integer"
            )
        _instance_id(self.instance_id)
        _identifier(self.request_id, "request_id")
        _canonical_sha256(self.request_sha256, "request_sha256")
        _canonical_sha256(self.command_sha256, "command_sha256")
        _aware_utc(self.expires_at, "expires_at")

    def to_row(self) -> tuple[object, ...]:
        self.validate()
        return (
            self.schema_version,
            self.principal_sha256,
            self.pair_id,
            self.session_id,
            self.session_epoch,
            self.instance_id,
            self.request_id,
            self.request_sha256,
            self.command_sha256,
            _iso(self.expires_at),
        )

    @classmethod
    def from_row(cls, row: object) -> "PrincipalDispatchIntent":
        if not hasattr(row, "keys"):
            raise PrincipalDispatchIntentError(
                "dispatch binding row is invalid"
            )
        keys = set(row.keys())  # type: ignore[union-attr]
        if keys != _DISPATCH_ROW_FIELDS:
            raise PrincipalDispatchIntentError(
                "dispatch binding row fields do not match schema"
            )
        schema = row["schema_version"]  # type: ignore[index]
        epoch = row["session_epoch"]  # type: ignore[index]
        if isinstance(schema, bool) or not isinstance(schema, int):
            raise PrincipalDispatchIntentError(
                "dispatch binding schema_version must be an integer"
            )
        if isinstance(epoch, bool) or not isinstance(epoch, int):
            raise PrincipalDispatchIntentError(
                "dispatch binding session_epoch must be an integer"
            )
        intent = cls(
            schema_version=schema,
            principal_sha256=_canonical_sha256(
                row["principal_sha256"], "principal_sha256"  # type: ignore[index]
            ),
            pair_id=_identifier(row["pair_id"], "pair_id"),  # type: ignore[index]
            session_id=_identifier(row["session_id"], "session_id"),  # type: ignore[index]
            session_epoch=epoch,
            instance_id=_instance_id(row["instance_id"]),  # type: ignore[index]
            request_id=_identifier(row["request_id"], "request_id"),  # type: ignore[index]
            request_sha256=_canonical_sha256(
                row["request_sha256"], "request_sha256"  # type: ignore[index]
            ),
            command_sha256=_canonical_sha256(
                row["command_sha256"], "command_sha256"  # type: ignore[index]
            ),
            expires_at=_parse_iso(row["expires_at"]),  # type: ignore[index]
        )
        intent.validate()
        return intent


class PrincipalDispatchIntentStore:
    """Atomically bind one idempotency claim to the Agent-dispatch path.

    The binding lives in the exact hardened IdempotencyStore SQLite database.
    A NEW claim inserts both the ordinary idempotency CLAIMED row and the exact
    dispatch binding in one BEGIN IMMEDIATE transaction. Therefore a later
    unresolved idempotency claim is resumable only when the matching dispatch
    binding was committed in the same transaction; a claim from any other path
    remains permanently ambiguous and can never become resumable merely because
    the caller retries.

    The binding is digest-only: it never stores request parameters, file content,
    pairing/session tokens, Agent credentials, or the raw principal subject.
    """

    def __init__(self, idempotency_store: IdempotencyStore) -> None:
        if not isinstance(idempotency_store, IdempotencyStore):
            raise TypeError(
                "idempotency_store must be an IdempotencyStore"
            )
        self.idempotency_store = idempotency_store
        self._initialize()

    @staticmethod
    def _rollback(connection) -> None:  # type: ignore[no-untyped-def]
        try:
            connection.execute("ROLLBACK")
        except Exception:
            pass

    def _initialize(self) -> None:
        with self.idempotency_store._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS principal_agent_dispatch_claims (
                    schema_version INTEGER NOT NULL,
                    principal_sha256 TEXT NOT NULL,
                    pair_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    session_epoch INTEGER NOT NULL,
                    instance_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    command_sha256 TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY(session_id, request_id)
                ) WITHOUT ROWID
                """
            )

    @staticmethod
    def _load_dispatch_row(
        connection,
        intent: PrincipalDispatchIntent,
    ):  # type: ignore[no-untyped-def]
        return connection.execute(
            """
            SELECT schema_version, principal_sha256, pair_id, session_id,
                   session_epoch, instance_id, request_id, request_sha256,
                   command_sha256, expires_at
            FROM principal_agent_dispatch_claims
            WHERE session_id = ? AND request_id = ?
            """,
            (intent.session_id, intent.request_id),
        ).fetchone()

    @staticmethod
    def _require_exact_dispatch_row(
        row: object,
        intent: PrincipalDispatchIntent,
    ) -> None:
        stored = PrincipalDispatchIntent.from_row(row)
        if stored != intent:
            raise PrincipalDispatchIntentConflictError(
                "idempotency key is bound to a different Agent dispatch authority"
            )

    def begin(
        self,
        intent: PrincipalDispatchIntent,
        *,
        now: datetime | None = None,
    ) -> PrincipalDispatchClaim:
        intent.validate()
        checked_at = _aware_utc(
            now or datetime.now(timezone.utc),
            "dispatch claim timestamp",
        )
        if checked_at >= intent.expires_at:
            raise PrincipalDispatchIntentError(
                "dispatch intent is already expired"
            )
        claimed_at = _utc_iso(checked_at)

        with self.idempotency_store._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                idempotency_row = connection.execute(
                    """
                    SELECT request_sha256, state, response_json, response_sha256,
                           claimed_at, completed_at
                    FROM idempotency_records
                    WHERE session_id = ? AND request_id = ?
                    """,
                    (intent.session_id, intent.request_id),
                ).fetchone()
                dispatch_row = self._load_dispatch_row(connection, intent)

                if idempotency_row is None:
                    if dispatch_row is not None:
                        raise PrincipalDispatchIntentError(
                            "dispatch binding exists without idempotency authority"
                        )
                    connection.execute(
                        """
                        INSERT INTO idempotency_records(
                            session_id, request_id, request_sha256,
                            state, claimed_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            intent.session_id,
                            intent.request_id,
                            intent.request_sha256,
                            IdempotencyState.CLAIMED.value,
                            claimed_at,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO principal_agent_dispatch_claims(
                            schema_version, principal_sha256, pair_id,
                            session_id, session_epoch, instance_id,
                            request_id, request_sha256, command_sha256,
                            expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        intent.to_row(),
                    )
                    connection.execute("COMMIT")
                    return PrincipalDispatchClaim(
                        state=PrincipalDispatchClaimState.NEW
                    )

                try:
                    state, replay = self.idempotency_store._validate_row(
                        idempotency_row,
                        expected_request_sha256=intent.request_sha256,
                    )
                except IdempotencyError as exc:
                    raise PrincipalDispatchIntentConflictError(
                        "idempotency authority conflicts with Agent dispatch request"
                    ) from exc

                if dispatch_row is None:
                    raise PrincipalDispatchIntentAmbiguousError(
                        "idempotency claim is not atomically bound to Agent dispatch"
                    )
                self._require_exact_dispatch_row(dispatch_row, intent)

                if state is IdempotencyState.CLAIMED:
                    connection.execute("COMMIT")
                    return PrincipalDispatchClaim(
                        state=PrincipalDispatchClaimState.RESUME
                    )
                if state is IdempotencyState.COMPLETED:
                    if replay is None:
                        raise PrincipalDispatchIntentError(
                            "completed idempotency authority lost replay receipt"
                        )
                    connection.execute("COMMIT")
                    return PrincipalDispatchClaim(
                        state=PrincipalDispatchClaimState.REPLAY,
                        replay_response=replay,
                    )
                raise PrincipalDispatchIntentError(
                    f"unsupported idempotency state: {state.value}"
                )
            except Exception:
                self._rollback(connection)
                raise
