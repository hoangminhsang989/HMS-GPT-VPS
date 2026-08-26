from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .idempotency_store import IdempotencyError, IdempotencyState, IdempotencyStore, _utc_iso
from .mcp_tunnel_ingress import current_mcp_tunnel_ingress_generation
from .principal_dispatch_intent import (
    PrincipalDispatchClaim,
    PrincipalDispatchClaimState,
    PrincipalDispatchIntent,
    PrincipalDispatchIntentAmbiguousError,
    PrincipalDispatchIntentConflictError,
    PrincipalDispatchIntentError,
    PrincipalDispatchIntentStore,
    _aware_utc,
    _canonical_sha256,
    _identifier,
    _instance_id,
)


MCP_INGRESS_DISPATCH_PROVENANCE_SCHEMA_VERSION = 1
_PROVENANCE_FIELDS = frozenset(
    {
        "schema_version",
        "principal_sha256",
        "pair_id",
        "session_id",
        "session_epoch",
        "instance_id",
        "request_id",
        "request_sha256",
        "command_sha256",
        "mcp_ingress_generation",
    }
)
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class McpIngressDispatchProvenance:
    schema_version: int
    principal_sha256: str
    pair_id: str
    session_id: str
    session_epoch: int
    instance_id: str
    request_id: str
    request_sha256: str
    command_sha256: str
    mcp_ingress_generation: str

    @staticmethod
    def _generation(value: object) -> str:
        if (
            not isinstance(value, str)
            or len(value) != 32
            or value != value.lower()
            or any(char not in _HEX for char in value)
        ):
            raise PrincipalDispatchIntentError("mcp_ingress_generation is noncanonical")
        return value

    def validate(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != MCP_INGRESS_DISPATCH_PROVENANCE_SCHEMA_VERSION
        ):
            raise PrincipalDispatchIntentError("unsupported ingress provenance schema")
        _canonical_sha256(self.principal_sha256, "principal_sha256")
        _identifier(self.pair_id, "pair_id")
        _identifier(self.session_id, "session_id")
        if isinstance(self.session_epoch, bool) or not isinstance(self.session_epoch, int) or self.session_epoch < 1:
            raise PrincipalDispatchIntentError("session_epoch must be a positive integer")
        _instance_id(self.instance_id)
        _identifier(self.request_id, "request_id")
        _canonical_sha256(self.request_sha256, "request_sha256")
        _canonical_sha256(self.command_sha256, "command_sha256")
        self._generation(self.mcp_ingress_generation)

    @classmethod
    def from_intent(cls, intent: PrincipalDispatchIntent, generation: str) -> "McpIngressDispatchProvenance":
        intent.validate()
        value = cls(
            schema_version=MCP_INGRESS_DISPATCH_PROVENANCE_SCHEMA_VERSION,
            principal_sha256=intent.principal_sha256,
            pair_id=intent.pair_id,
            session_id=intent.session_id,
            session_epoch=intent.session_epoch,
            instance_id=intent.instance_id,
            request_id=intent.request_id,
            request_sha256=intent.request_sha256,
            command_sha256=intent.command_sha256,
            mcp_ingress_generation=cls._generation(generation),
        )
        value.validate()
        return value

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
            self.mcp_ingress_generation,
        )

    @classmethod
    def from_row(cls, row: object) -> "McpIngressDispatchProvenance":
        if not hasattr(row, "keys") or frozenset(row.keys()) != _PROVENANCE_FIELDS:  # type: ignore[union-attr]
            raise PrincipalDispatchIntentError("ingress provenance row fields differ")
        schema = row["schema_version"]  # type: ignore[index]
        epoch = row["session_epoch"]  # type: ignore[index]
        value = cls(
            schema_version=schema,
            principal_sha256=row["principal_sha256"],  # type: ignore[index]
            pair_id=row["pair_id"],  # type: ignore[index]
            session_id=row["session_id"],  # type: ignore[index]
            session_epoch=epoch,
            instance_id=row["instance_id"],  # type: ignore[index]
            request_id=row["request_id"],  # type: ignore[index]
            request_sha256=row["request_sha256"],  # type: ignore[index]
            command_sha256=row["command_sha256"],  # type: ignore[index]
            mcp_ingress_generation=row["mcp_ingress_generation"],  # type: ignore[index]
        )
        value.validate()
        return value

    def require_exact_intent(self, intent: PrincipalDispatchIntent) -> None:
        expected = McpIngressDispatchProvenance.from_intent(
            intent,
            self.mcp_ingress_generation,
        )
        if self != expected:
            raise PrincipalDispatchIntentAmbiguousError(
                "ingress provenance differs from exact Agent dispatch authority"
            )


class IngressProvenancePrincipalDispatchIntentStore(PrincipalDispatchIntentStore):
    """Extend the principal dispatch transaction with non-secret MCP ingress provenance."""

    def __init__(self, idempotency_store: IdempotencyStore) -> None:
        super().__init__(idempotency_store)
        self._initialize_ingress_provenance()

    def _initialize_ingress_provenance(self) -> None:
        with self.idempotency_store._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS principal_dispatch_ingress_provenance (
                    schema_version INTEGER NOT NULL,
                    principal_sha256 TEXT NOT NULL,
                    pair_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    session_epoch INTEGER NOT NULL,
                    instance_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    command_sha256 TEXT NOT NULL,
                    mcp_ingress_generation TEXT NOT NULL,
                    PRIMARY KEY(session_id, request_id)
                ) WITHOUT ROWID
                """
            )
            rows = connection.execute(
                "PRAGMA table_info(principal_dispatch_ingress_provenance)"
            ).fetchall()
            expected = [
                ("schema_version", "INTEGER", 1, 0),
                ("principal_sha256", "TEXT", 1, 0),
                ("pair_id", "TEXT", 1, 0),
                ("session_id", "TEXT", 1, 1),
                ("session_epoch", "INTEGER", 1, 0),
                ("instance_id", "TEXT", 1, 0),
                ("request_id", "TEXT", 1, 2),
                ("request_sha256", "TEXT", 1, 0),
                ("command_sha256", "TEXT", 1, 0),
                ("mcp_ingress_generation", "TEXT", 1, 0),
            ]
            observed = [
                (row["name"], row["type"], row["notnull"], row["pk"])
                for row in rows
            ]
            if observed != expected or any(row["dflt_value"] is not None for row in rows):
                raise PrincipalDispatchIntentError(
                    "ingress provenance table schema differs from authority"
                )
            master = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                ("principal_dispatch_ingress_provenance",),
            ).fetchone()
            if (
                master is None
                or not isinstance(master["sql"], str)
                or "WITHOUT ROWID" not in master["sql"].upper()
            ):
                raise PrincipalDispatchIntentError(
                    "ingress provenance table storage authority differs"
                )

    @staticmethod
    def _load_provenance_row(connection, intent: PrincipalDispatchIntent):  # type: ignore[no-untyped-def]
        return connection.execute(
            """
            SELECT schema_version, principal_sha256, pair_id, session_id,
                   session_epoch, instance_id, request_id, request_sha256,
                   command_sha256, mcp_ingress_generation
            FROM principal_dispatch_ingress_provenance
            WHERE session_id = ? AND request_id = ?
            """,
            (intent.session_id, intent.request_id),
        ).fetchone()

    @staticmethod
    def _require_existing_provenance_authority(
        row: object | None,
        intent: PrincipalDispatchIntent,
        current_generation: str | None,
    ) -> None:
        if row is None:
            if current_generation is not None:
                raise PrincipalDispatchIntentAmbiguousError(
                    "existing dispatch lacks atomic MCP ingress provenance"
                )
            return
        stored = McpIngressDispatchProvenance.from_row(row)
        stored.require_exact_intent(intent)
        if current_generation is None:
            raise PrincipalDispatchIntentAmbiguousError(
                "MCP-proven dispatch cannot resume outside protected MCP ingress"
            )
        # A retry may arrive through a later tunnel generation after a service
        # restart. The immutable provenance remains bound to the original NEW
        # dispatch generation and is never rewritten by retry/replay.

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
            raise PrincipalDispatchIntentError("dispatch intent is already expired")
        claimed_at = _utc_iso(checked_at)
        current_generation = current_mcp_tunnel_ingress_generation()

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
                provenance_row = self._load_provenance_row(connection, intent)

                if idempotency_row is None:
                    if dispatch_row is not None or provenance_row is not None:
                        raise PrincipalDispatchIntentError(
                            "dispatch/provenance authority exists without idempotency authority"
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
                    if current_generation is not None:
                        provenance = McpIngressDispatchProvenance.from_intent(
                            intent,
                            current_generation,
                        )
                        connection.execute(
                            """
                            INSERT INTO principal_dispatch_ingress_provenance(
                                schema_version, principal_sha256, pair_id,
                                session_id, session_epoch, instance_id,
                                request_id, request_sha256, command_sha256,
                                mcp_ingress_generation
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            provenance.to_row(),
                        )
                    connection.execute("COMMIT")
                    return PrincipalDispatchClaim(state=PrincipalDispatchClaimState.NEW)

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
                self._require_existing_provenance_authority(
                    provenance_row,
                    intent,
                    current_generation,
                )

                if state is IdempotencyState.CLAIMED:
                    connection.execute("COMMIT")
                    return PrincipalDispatchClaim(state=PrincipalDispatchClaimState.RESUME)
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
