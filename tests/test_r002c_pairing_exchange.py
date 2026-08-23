from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from hms_gpt_vps.control_session_store import ControlSessionStore
from hms_gpt_vps.pairing import issue_pairing_grant
from hms_gpt_vps.pairing_exchange import (
    PAIRING_EXCHANGE_RECOVERY_SECONDS,
    PairingExchangeIntegrityError,
    PairingExchangeKey,
    PairingExchangeRecoveryExpiredError,
    PairingExchangeRecoveryMismatchError,
    PairingExchangeStoreMismatchError,
    PairingSessionExchange,
)
from hms_gpt_vps.pairing_store import PairingStore


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)
INSTANCE_ID = "hms-01"
CLIENT_NONCE = "client-nonce-0123456789"


def build_exchange(tmp_path, *, key_bytes: bytes = b"K" * 32):
    db_path = tmp_path / "auth.sqlite3"
    pairing_store = PairingStore(db_path)
    session_store = ControlSessionStore(db_path)
    exchange = PairingSessionExchange(
        pairing_store,
        session_store,
        PairingExchangeKey(key_bytes),
    )
    pair = issue_pairing_grant(
        INSTANCE_ID,
        "https://bridge.example.test",
        scopes=("workspace.read", "workspace.write"),
        now=NOW,
    )
    pairing_store.create(pair.record)
    return exchange, pair, pairing_store, session_store, db_path


def count_sessions(db_path) -> int:
    with sqlite3.connect(db_path) as connection:
        return int(connection.execute("SELECT COUNT(*) FROM control_sessions").fetchone()[0])


def test_exchange_atomically_consumes_pairing_and_creates_one_session(tmp_path) -> None:
    exchange, pair, pairing_store, session_store, db_path = build_exchange(tmp_path)
    issued = exchange.exchange(
        pair.record.pair_id,
        pair.token,
        CLIENT_NONCE,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )

    stored_pair = pairing_store.require(pair.record.pair_id)
    stored_session = session_store.require(issued.record.session_id)
    assert stored_pair.consumed_at == NOW + timedelta(seconds=1)
    assert stored_session == issued.record
    assert count_sessions(db_path) == 1


def test_retry_within_recovery_window_returns_exact_same_session(tmp_path) -> None:
    exchange, pair, _pairing_store, _session_store, db_path = build_exchange(tmp_path)
    first = exchange.exchange(
        pair.record.pair_id,
        pair.token,
        CLIENT_NONCE,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )
    replay = exchange.exchange(
        pair.record.pair_id,
        pair.token,
        CLIENT_NONCE,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=30),
    )

    assert replay.record == first.record
    assert replay.token == first.token
    assert count_sessions(db_path) == 1


def test_retry_with_different_client_nonce_is_rejected(tmp_path) -> None:
    exchange, pair, _pairing_store, _session_store, db_path = build_exchange(tmp_path)
    first = exchange.exchange(
        pair.record.pair_id,
        pair.token,
        CLIENT_NONCE,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )

    with pytest.raises(PairingExchangeRecoveryMismatchError, match="client nonce"):
        exchange.exchange(
            pair.record.pair_id,
            pair.token,
            "different-nonce-0123456789",
            instance_id=INSTANCE_ID,
            now=NOW + timedelta(seconds=10),
        )

    assert count_sessions(db_path) == 1
    assert _session_store.require(first.record.session_id) == first.record


def test_retry_after_recovery_window_fails_closed(tmp_path) -> None:
    exchange, pair, _pairing_store, _session_store, _db_path = build_exchange(tmp_path)
    exchange.exchange(
        pair.record.pair_id,
        pair.token,
        CLIENT_NONCE,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )

    with pytest.raises(PairingExchangeRecoveryExpiredError, match="expired"):
        exchange.exchange(
            pair.record.pair_id,
            pair.token,
            CLIENT_NONCE,
            instance_id=INSTANCE_ID,
            now=NOW + timedelta(seconds=PAIRING_EXCHANGE_RECOVERY_SECONDS + 2),
        )


def test_recovery_with_different_bridge_key_is_rejected(tmp_path) -> None:
    exchange, pair, pairing_store, session_store, _db_path = build_exchange(tmp_path)
    exchange.exchange(
        pair.record.pair_id,
        pair.token,
        CLIENT_NONCE,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )
    wrong_key_exchange = PairingSessionExchange(
        pairing_store,
        session_store,
        PairingExchangeKey(b"Z" * 32),
    )

    with pytest.raises(PairingExchangeIntegrityError, match="session identity"):
        wrong_key_exchange.exchange(
            pair.record.pair_id,
            pair.token,
            CLIENT_NONCE,
            instance_id=INSTANCE_ID,
            now=NOW + timedelta(seconds=10),
        )


def test_rotated_initial_session_cannot_be_recovered_from_old_pairing_token(tmp_path) -> None:
    exchange, pair, _pairing_store, session_store, _db_path = build_exchange(tmp_path)
    issued = exchange.exchange(
        pair.record.pair_id,
        pair.token,
        CLIENT_NONCE,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )
    session_store.rotate(
        issued.record.session_id,
        issued.token,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=5),
    )

    with pytest.raises(PairingExchangeIntegrityError, match="changed"):
        exchange.exchange(
            pair.record.pair_id,
            pair.token,
            CLIENT_NONCE,
            instance_id=INSTANCE_ID,
            now=NOW + timedelta(seconds=10),
        )


def test_exchange_requires_pairing_and_session_tables_in_same_database(tmp_path) -> None:
    pairing_store = PairingStore(tmp_path / "pairing.sqlite3")
    session_store = ControlSessionStore(tmp_path / "session.sqlite3")
    with pytest.raises(PairingExchangeStoreMismatchError, match="shared SQLite"):
        PairingSessionExchange(
            pairing_store,
            session_store,
            PairingExchangeKey(b"K" * 32),
        )


def test_raw_pairing_session_nonce_and_bridge_key_are_not_stored_in_sqlite(tmp_path) -> None:
    key_bytes = b"bridge-exchange-key-material!!" + b"XX"
    assert len(key_bytes) >= 32
    exchange, pair, _pairing_store, _session_store, db_path = build_exchange(
        tmp_path,
        key_bytes=key_bytes,
    )
    session = exchange.exchange(
        pair.record.pair_id,
        pair.token,
        CLIENT_NONCE,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )

    raw_db = db_path.read_bytes()
    assert pair.token.encode("utf-8") not in raw_db
    assert session.token.encode("utf-8") not in raw_db
    assert CLIENT_NONCE.encode("utf-8") not in raw_db
    assert key_bytes not in raw_db


def test_exchange_key_repr_does_not_reveal_secret() -> None:
    secret = b"S" * 32
    key = PairingExchangeKey(secret)
    assert "SSSS" not in repr(key)
