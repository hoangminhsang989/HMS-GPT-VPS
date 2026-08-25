from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

import pytest

import hms_gpt_vps.control_session_store as control_session_store_module
from hms_gpt_vps.control_session import (
    ControlSessionError,
    ControlSessionRecord,
    issue_control_session,
)
from hms_gpt_vps.control_session_store import (
    ControlSessionStore,
    ControlSessionStoreError,
)
from hms_gpt_vps.pairing import consume_pairing_record, issue_pairing_grant
from hms_gpt_vps.pairing_exchange import (
    PairingExchangeKey,
    PairingExchangeStoreMismatchError,
    PairingSessionExchange,
)
from hms_gpt_vps.pairing_store import PairingStore


NOW = datetime(2026, 8, 25, 6, 0, tzinfo=timezone.utc)
INSTANCE_ID = "hms-01"
CLIENT_NONCE = "client-nonce-0123456789"


def consumed_pairing():
    grant = issue_pairing_grant(
        INSTANCE_ID,
        "https://bridge.example.test",
        scopes=("workspace.read", "workspace.write"),
        now=NOW,
    )
    consumed = consume_pairing_record(
        grant.record,
        grant.token,
        instance_id=INSTANCE_ID,
        now=NOW + timedelta(seconds=1),
    )
    return grant, consumed


def canonical_session_record() -> ControlSessionRecord:
    _pair_grant, pairing = consumed_pairing()
    return issue_control_session(
        pairing,
        now=NOW + timedelta(seconds=2),
    ).record


@pytest.mark.parametrize("bad_schema", [True, "1", 1.0, None])
def test_control_session_from_dict_rejects_schema_coercion(bad_schema: object) -> None:
    payload = canonical_session_record().to_dict()
    payload["schema_version"] = bad_schema
    with pytest.raises(ControlSessionError, match="schema_version"):
        ControlSessionRecord.from_dict(payload)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("session_id", 7),
        ("family_id", False),
        ("instance_id", ["hms-01"]),
        ("token_sha256", 123),
        ("rotated_from", 9),
        ("revocation_reason", {"reason": "x"}),
    ],
)
def test_control_session_from_dict_rejects_string_coercion(
    field: str,
    bad_value: object,
) -> None:
    payload = canonical_session_record().to_dict()
    payload[field] = bad_value
    with pytest.raises(ControlSessionError):
        ControlSessionRecord.from_dict(payload)


def test_control_session_rejects_unknown_field_and_uppercase_digest() -> None:
    payload = canonical_session_record().to_dict()
    payload["extra"] = True
    with pytest.raises(ControlSessionError, match="fields"):
        ControlSessionRecord.from_dict(payload)

    payload = canonical_session_record().to_dict()
    payload["token_sha256"] = "A" * 64
    with pytest.raises(ControlSessionError, match="lowercase"):
        ControlSessionRecord.from_dict(payload)


@pytest.mark.parametrize("ttl", [True, 60.0, "60", 59, 86401])
def test_control_session_ttl_is_exact_integer(ttl: object) -> None:
    _pair_grant, pairing = consumed_pairing()
    with pytest.raises(ControlSessionError, match="integer"):
        issue_control_session(
            pairing,
            now=NOW + timedelta(seconds=2),
            ttl_seconds=ttl,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), 31])
def test_control_session_store_rejects_invalid_timeout(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        ControlSessionStore(
            tmp_path / "sessions.sqlite3",
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


def test_control_session_store_rejects_symlinked_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    redirected = tmp_path / "redirected"
    try:
        redirected.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")

    with pytest.raises(ControlSessionStoreError, match="link|reparse"):
        ControlSessionStore(redirected / "sessions.sqlite3")


def test_control_session_store_rejects_database_replacement(tmp_path: Path) -> None:
    _pair_grant, pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))
    store = ControlSessionStore(tmp_path / "sessions.sqlite3")
    store.create(grant)

    original = store.path
    moved = tmp_path / "sessions-original.sqlite3"
    original.replace(moved)
    original.write_bytes(moved.read_bytes())

    with pytest.raises(ControlSessionStoreError, match="startup authority"):
        store.require(grant.record.session_id)


def test_control_session_store_rejects_tampered_row_epoch_type(tmp_path: Path) -> None:
    _pair_grant, pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))
    store = ControlSessionStore(tmp_path / "sessions.sqlite3")
    store.create(grant)

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE control_sessions SET epoch = ? WHERE session_id = ?",
            ("4x", grant.record.session_id),
        )

    with pytest.raises(ControlSessionStoreError, match="epoch"):
        store.require(grant.record.session_id)


def test_control_session_store_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    _pair_grant, pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))
    store = ControlSessionStore(tmp_path / "sessions.sqlite3")
    store.create(grant)
    raw = store._serialize(grant.record)
    duplicate = raw[:-1] + ',"schema_version":1}'

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE control_sessions SET record_json = ? WHERE session_id = ?",
            (duplicate, grant.record.session_id),
        )

    with pytest.raises(ControlSessionStoreError, match="duplicate"):
        store.require(grant.record.session_id)


class _ExplodingPragmaConnection:
    def __init__(self) -> None:
        self.row_factory: object | None = None
        self.closed = False

    def execute(self, statement: str, *args: object) -> object:
        raise RuntimeError(f"forced setup failure: {statement}")

    def close(self) -> None:
        self.closed = True


def test_control_session_store_closes_connection_when_setup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _ExplodingPragmaConnection()
    monkeypatch.setattr(
        control_session_store_module.sqlite3,
        "connect",
        lambda *args, **kwargs: connection,
    )

    with pytest.raises(RuntimeError, match="forced setup failure"):
        ControlSessionStore(tmp_path / "cleanup.sqlite3")

    assert connection.closed is True


def build_exchange(tmp_path: Path):
    path = tmp_path / "auth.sqlite3"
    pairing_store = PairingStore(path)
    session_store = ControlSessionStore(path)
    exchange = PairingSessionExchange(
        pairing_store,
        session_store,
        PairingExchangeKey(b"K" * 32),
    )
    grant = issue_pairing_grant(
        INSTANCE_ID,
        "https://bridge.example.test",
        scopes=("workspace.read", "workspace.write"),
        now=NOW,
    )
    pairing_store.create(grant.record)
    return exchange, grant, pairing_store, session_store


def test_pairing_exchange_rejects_database_replacement_after_startup(
    tmp_path: Path,
) -> None:
    exchange, grant, _pairing_store, _session_store = build_exchange(tmp_path)
    original = exchange.path
    moved = tmp_path / "auth-original.sqlite3"
    original.replace(moved)
    original.write_bytes(moved.read_bytes())

    with pytest.raises(PairingExchangeStoreMismatchError, match="authority changed"):
        exchange.exchange(
            grant.record.pair_id,
            grant.token,
            CLIENT_NONCE,
            instance_id=INSTANCE_ID,
            now=NOW + timedelta(seconds=1),
        )


def test_pairing_exchange_rejects_stores_with_different_startup_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "auth.sqlite3"
    pairing_store = PairingStore(path)

    moved = tmp_path / "first.sqlite3"
    path.replace(moved)
    path.write_bytes(moved.read_bytes())
    session_store = ControlSessionStore(path)

    with pytest.raises(PairingExchangeStoreMismatchError, match="startup database identity"):
        PairingSessionExchange(
            pairing_store,
            session_store,
            PairingExchangeKey(b"K" * 32),
        )
