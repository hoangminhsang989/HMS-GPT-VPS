from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sqlite3

from .control_session import (
    DEFAULT_SESSION_TTL_SECONDS,
    SESSION_SCHEMA_VERSION,
    ControlSessionGrant,
    ControlSessionRecord,
)
from .control_session_store import ControlSessionStore
from .pairing import (
    PairingRecord,
    PairingRevokedError,
    PairingTokenMismatchError,
    consume_pairing_record,
)
from .pairing_store import PairingNotFoundError, PairingStore


PAIRING_EXCHANGE_RECOVERY_SECONDS = 60
PAIRING_EXCHANGE_KEY_BYTES = 32
PAIRING_EXCHANGE_NONCE_BYTES = 16
_PAIRING_EXCHANGE_DOMAIN = b"hms-gpt-vps/pairing-exchange/v2"
_NONCE_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


class PairingExchangeError(RuntimeError):
    pass


class PairingExchangeStoreMismatchError(PairingExchangeError):
    pass


class PairingExchangeRecoveryExpiredError(PairingExchangeError):
    pass


class PairingExchangeRecoveryMismatchError(PairingExchangeError):
    pass


class PairingExchangeIntegrityError(PairingExchangeError):
    pass


@dataclass(frozen=True)
class PairingExchangeKey:
    """Bridge-held secret used only to derive recoverable initial sessions.

    The key must be persisted by the trusted Bridge secret store (DPAPI on the
    Windows product path). It is deliberately never written to pairing/session
    SQLite and is excluded from repr output.
    """

    value: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes):
            raise TypeError("pairing exchange key must be bytes")
        if len(self.value) < PAIRING_EXCHANGE_KEY_BYTES:
            raise ValueError("pairing exchange key must contain at least 32 bytes")

    @classmethod
    def generate(cls) -> "PairingExchangeKey":
        return cls(secrets.token_bytes(PAIRING_EXCHANGE_KEY_BYTES))

    def export_for_secret_store(self) -> bytes:
        return bytes(self.value)


def generate_pairing_exchange_nonce() -> str:
    """Generate the client-side replay binder for one pairing exchange."""
    return secrets.token_urlsafe(PAIRING_EXCHANGE_NONCE_BYTES)


def _validate_client_nonce(value: str) -> None:
    if not isinstance(value, str) or not (20 <= len(value) <= 128):
        raise PairingExchangeError("pairing exchange client nonce is invalid")
    if any(char not in _NONCE_ALLOWED for char in value):
        raise PairingExchangeError(
            "pairing exchange client nonce contains unsupported characters"
        )


def _nonce_digest(value: str) -> str:
    _validate_client_nonce(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aware_utc(value: datetime | None) -> datetime:
    checked = value or datetime.now(timezone.utc)
    if checked.tzinfo is None or checked.utcoffset() is None:
        raise PairingExchangeError("pairing exchange timestamp must be timezone-aware")
    return checked.astimezone(timezone.utc)


def _serialize_pairing(record: PairingRecord) -> str:
    record.validate()
    return json.dumps(
        record.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _deserialize_pairing(raw: str) -> PairingRecord:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PairingExchangeIntegrityError(
            "stored pairing exchange record is invalid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise PairingExchangeIntegrityError(
            "stored pairing exchange record must be an object"
        )
    try:
        return PairingRecord.from_dict(payload)
    except ValueError as exc:
        raise PairingExchangeIntegrityError(
            "stored pairing exchange record failed validation"
        ) from exc


def _serialize_session(record: ControlSessionRecord) -> str:
    record.validate()
    return json.dumps(
        record.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _deserialize_session(raw: str) -> ControlSessionRecord:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PairingExchangeIntegrityError(
            "stored exchange session is invalid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise PairingExchangeIntegrityError("stored exchange session must be an object")
    try:
        return ControlSessionRecord.from_dict(payload)
    except ValueError as exc:
        raise PairingExchangeIntegrityError(
            "stored exchange session failed validation"
        ) from exc


def _pair_token_digest(token: str) -> str:
    if not token:
        raise PairingTokenMismatchError("pairing token is required")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _authenticate_pair_token(record: PairingRecord, token: str, instance_id: str) -> None:
    record.validate()
    if instance_id != record.instance_id:
        raise PairingTokenMismatchError("pairing instance mismatch")
    if record.revoked_at is not None:
        raise PairingRevokedError("pairing grant is revoked")
    if not hmac.compare_digest(_pair_token_digest(token), record.token_sha256):
        raise PairingTokenMismatchError("pairing token mismatch")


def _derive_material(
    key: PairingExchangeKey,
    label: bytes,
    record: PairingRecord,
    pair_token: str,
    client_nonce: str,
) -> bytes:
    _validate_client_nonce(client_nonce)
    message = b"\x00".join(
        (
            _PAIRING_EXCHANGE_DOMAIN,
            label,
            record.pair_id.encode("utf-8"),
            record.instance_id.encode("utf-8"),
            pair_token.encode("utf-8"),
            client_nonce.encode("utf-8"),
        )
    )
    return hmac.new(key.value, message, hashlib.sha256).digest()


def _urlsafe(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def derive_initial_session_grant(
    record: PairingRecord,
    pair_token: str,
    client_nonce: str,
    key: PairingExchangeKey,
) -> ControlSessionGrant:
    """Derive exactly one initial session from an already-consumed pairing.

    Recovery requires three values: the one-time pairing token, the client-side
    nonce from the original exchange request, and the Bridge-held root key. The
    database stores only the nonce SHA-256. Determinism is used solely so a
    post-commit/pre-response crash can return the exact same session during the
    bounded recovery window without storing the raw session token.
    """
    record.validate()
    if record.consumed_at is None:
        raise PairingExchangeError("pairing must be consumed before deriving a session")
    _authenticate_pair_token(record, pair_token, record.instance_id)
    _validate_client_nonce(client_nonce)

    session_token = _urlsafe(
        _derive_material(
            key,
            b"session-token",
            record,
            pair_token,
            client_nonce,
        )
    )
    session_id = _urlsafe(
        _derive_material(
            key,
            b"session-id",
            record,
            pair_token,
            client_nonce,
        )[:18]
    )
    family_id = _urlsafe(
        _derive_material(
            key,
            b"family-id",
            record,
            pair_token,
            client_nonce,
        )[:18]
    )
    issued_at = record.consumed_at.astimezone(timezone.utc)
    session_record = ControlSessionRecord(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id=session_id,
        family_id=family_id,
        instance_id=record.instance_id,
        token_sha256=hashlib.sha256(session_token.encode("utf-8")).hexdigest(),
        scopes=record.scopes,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=DEFAULT_SESSION_TTL_SECONDS),
        epoch=1,
    )
    session_record.validate()
    return ControlSessionGrant(record=session_record, token=session_token)


class PairingSessionExchange:
    """Atomic pairing->initial-session exchange over one shared SQLite file.

    Both PairingStore and ControlSessionStore must point to the same database so
    consuming the pairing, persisting the nonce digest and inserting its initial
    session can commit in one transaction. A retry after commit must provide the
    exact original client nonce and may recover the same session only during a
    short window; it never creates a second session or stores raw credentials.
    """

    def __init__(
        self,
        pairing_store: PairingStore,
        session_store: ControlSessionStore,
        key: PairingExchangeKey,
    ) -> None:
        if pairing_store.path != session_store.path:
            raise PairingExchangeStoreMismatchError(
                "crash-safe pairing exchange requires one shared SQLite database"
            )
        self.pairing_store = pairing_store
        self.session_store = session_store
        self.key = key
        self.path: Path = pairing_store.path
        self.timeout_seconds = min(
            pairing_store.timeout_seconds,
            session_store.timeout_seconds,
        )
        self._initialize_exchange_table()

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

    def _initialize_exchange_table(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pairing_exchanges (
                    pair_id TEXT PRIMARY KEY NOT NULL,
                    nonce_sha256 TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    FOREIGN KEY(pair_id) REFERENCES pairing_records(pair_id),
                    FOREIGN KEY(session_id) REFERENCES control_sessions(session_id)
                ) WITHOUT ROWID
                """
            )

    def exchange(
        self,
        pair_id: str,
        pair_token: str,
        client_nonce: str,
        *,
        instance_id: str,
        now: datetime | None = None,
    ) -> ControlSessionGrant:
        checked_at = _aware_utc(now)
        nonce_sha256 = _nonce_digest(client_nonce)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT instance_id, record_json FROM pairing_records WHERE pair_id = ?",
                (pair_id,),
            ).fetchone()
            if row is None:
                raise PairingNotFoundError(f"pairing record not found: {pair_id}")

            record = _deserialize_pairing(str(row["record_json"]))
            if str(row["instance_id"]) != record.instance_id:
                raise PairingExchangeIntegrityError("pairing row instance identity mismatch")

            if record.consumed_at is None:
                consumed = consume_pairing_record(
                    record,
                    pair_token,
                    instance_id=instance_id,
                    now=checked_at,
                )
                grant = derive_initial_session_grant(
                    consumed,
                    pair_token,
                    client_nonce,
                    self.key,
                )
                collision = connection.execute(
                    "SELECT record_json FROM control_sessions WHERE session_id = ?",
                    (grant.record.session_id,),
                ).fetchone()
                if collision is not None:
                    raise PairingExchangeIntegrityError(
                        "derived initial session already exists before pairing consumption"
                    )
                existing_exchange = connection.execute(
                    "SELECT pair_id FROM pairing_exchanges WHERE pair_id = ?",
                    (pair_id,),
                ).fetchone()
                if existing_exchange is not None:
                    raise PairingExchangeIntegrityError(
                        "unconsumed pairing already has an exchange binding"
                    )

                connection.execute(
                    "UPDATE pairing_records SET record_json = ? WHERE pair_id = ?",
                    (_serialize_pairing(consumed), pair_id),
                )
                session = grant.record
                connection.execute(
                    """
                    INSERT INTO control_sessions(
                        session_id, family_id, instance_id, epoch, record_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        session.session_id,
                        session.family_id,
                        session.instance_id,
                        session.epoch,
                        _serialize_session(session),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO pairing_exchanges(pair_id, nonce_sha256, session_id)
                    VALUES (?, ?, ?)
                    """,
                    (pair_id, nonce_sha256, session.session_id),
                )
                connection.execute("COMMIT")
                return grant

            _authenticate_pair_token(record, pair_token, instance_id)
            consumed_at = record.consumed_at.astimezone(timezone.utc)
            if checked_at < consumed_at:
                raise PairingExchangeError("pairing recovery time precedes consumption")
            if checked_at - consumed_at > timedelta(
                seconds=PAIRING_EXCHANGE_RECOVERY_SECONDS
            ):
                raise PairingExchangeRecoveryExpiredError(
                    "pairing exchange recovery window has expired"
                )

            exchange_row = connection.execute(
                """
                SELECT nonce_sha256, session_id
                FROM pairing_exchanges
                WHERE pair_id = ?
                """,
                (pair_id,),
            ).fetchone()
            if exchange_row is None:
                raise PairingExchangeIntegrityError(
                    "consumed pairing has no atomically committed exchange binding"
                )
            stored_nonce_sha256 = str(exchange_row["nonce_sha256"])
            if not hmac.compare_digest(stored_nonce_sha256.lower(), nonce_sha256.lower()):
                raise PairingExchangeRecoveryMismatchError(
                    "pairing exchange client nonce does not match original request"
                )

            grant = derive_initial_session_grant(
                record,
                pair_token,
                client_nonce,
                self.key,
            )
            stored_session_id = str(exchange_row["session_id"])
            if grant.record.session_id != stored_session_id:
                raise PairingExchangeIntegrityError(
                    "derived session identity no longer matches exchange binding"
                )
            session_row = connection.execute(
                "SELECT record_json FROM control_sessions WHERE session_id = ?",
                (stored_session_id,),
            ).fetchone()
            if session_row is None:
                raise PairingExchangeIntegrityError(
                    "consumed pairing has no atomically committed initial session"
                )
            stored_session = _deserialize_session(str(session_row["record_json"]))
            if stored_session.to_dict() != grant.record.to_dict():
                raise PairingExchangeIntegrityError(
                    "initial session changed; pairing recovery is no longer permitted"
                )
            connection.execute("COMMIT")
            return grant
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
