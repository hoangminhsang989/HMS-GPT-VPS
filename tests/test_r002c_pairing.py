from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest

from hms_gpt_vps.pairing import (
    PAIRABLE_SCOPES,
    PairingConsumedError,
    PairingError,
    PairingExpiredError,
    PairingRecord,
    PairingRevokedError,
    PairingTokenMismatchError,
    issue_pairing_grant,
    verify_pairing_token,
)
from hms_gpt_vps.pairing_store import PairingAlreadyExistsError, PairingStore


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)


def test_pairing_grant_uses_fragment_and_never_persists_plaintext_token() -> None:
    grant = issue_pairing_grant(
        "hms-01",
        "https://bridge.example.test/hms",
        now=NOW,
    )

    assert grant.pairing_link.startswith(
        f"https://bridge.example.test/hms/pair/{grant.record.pair_id}#token="
    )
    assert "?token=" not in grant.pairing_link
    assert len(grant.token) >= 43
    assert grant.token not in repr(grant)
    assert grant.token not in repr(grant.record)
    assert grant.token not in str(grant.record.to_dict())
    assert grant.record.token_sha256 != grant.token
    assert set(grant.record.scopes) == PAIRABLE_SCOPES


def test_pairing_requires_https_and_supported_scopes() -> None:
    with pytest.raises(PairingError, match="HTTPS"):
        issue_pairing_grant("hms-01", "http://bridge.example.test", now=NOW)

    with pytest.raises(PairingError, match="unsupported pairing scope"):
        issue_pairing_grant(
            "hms-01",
            "https://bridge.example.test",
            scopes={"workspace.read", "host.admin"},
            now=NOW,
        )


def test_pairing_record_parser_rejects_missing_required_timestamps() -> None:
    grant = issue_pairing_grant("hms-01", "https://bridge.example.test", now=NOW)
    payload = grant.record.to_dict()
    payload.pop("issued_at")
    with pytest.raises(PairingError, match="issued_at and expires_at are required"):
        PairingRecord.from_dict(payload)

    payload = grant.record.to_dict()
    payload.pop("expires_at")
    with pytest.raises(PairingError, match="issued_at and expires_at are required"):
        PairingRecord.from_dict(payload)


def test_pairing_verification_rejects_wrong_instance_token_and_expiry() -> None:
    grant = issue_pairing_grant("hms-01", "https://bridge.example.test", now=NOW)

    with pytest.raises(PairingTokenMismatchError, match="instance mismatch"):
        verify_pairing_token(
            grant.record,
            grant.token,
            instance_id="other",
            now=NOW,
        )

    with pytest.raises(PairingTokenMismatchError, match="token mismatch"):
        verify_pairing_token(
            grant.record,
            "wrong-token",
            instance_id="hms-01",
            now=NOW,
        )

    with pytest.raises(PairingExpiredError, match="expired"):
        verify_pairing_token(
            grant.record,
            grant.token,
            instance_id="hms-01",
            now=grant.record.expires_at,
        )


def test_pairing_store_never_writes_raw_token_to_sqlite(tmp_path: Path) -> None:
    db_path = tmp_path / "pairing.sqlite3"
    store = PairingStore(db_path)
    grant = issue_pairing_grant("hms-01", "https://bridge.example.test", now=NOW)
    store.create(grant.record)

    raw_database = db_path.read_bytes()
    assert grant.token.encode("utf-8") not in raw_database
    loaded = store.require(grant.record.pair_id)
    assert loaded == grant.record

    with pytest.raises(PairingAlreadyExistsError):
        store.create(grant.record)


def test_pairing_store_consumes_exactly_once(tmp_path: Path) -> None:
    store = PairingStore(tmp_path / "pairing.sqlite3")
    grant = issue_pairing_grant("hms-01", "https://bridge.example.test", now=NOW)
    store.create(grant.record)

    consumed = store.consume(
        grant.record.pair_id,
        grant.token,
        instance_id="hms-01",
        now=NOW + timedelta(seconds=1),
    )
    assert consumed.consumed_at == NOW + timedelta(seconds=1)

    with pytest.raises(PairingConsumedError, match="already consumed"):
        store.consume(
            grant.record.pair_id,
            grant.token,
            instance_id="hms-01",
            now=NOW + timedelta(seconds=2),
        )


def test_pairing_store_atomic_concurrent_consume_has_one_winner(tmp_path: Path) -> None:
    store = PairingStore(tmp_path / "pairing.sqlite3", timeout_seconds=10)
    grant = issue_pairing_grant("hms-01", "https://bridge.example.test", now=NOW)
    store.create(grant.record)
    barrier = Barrier(2)

    def consume_once() -> str:
        barrier.wait(timeout=5)
        try:
            store.consume(
                grant.record.pair_id,
                grant.token,
                instance_id="hms-01",
                now=NOW + timedelta(seconds=1),
            )
            return "consumed"
        except PairingConsumedError:
            return "already-consumed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(lambda _: consume_once(), range(2)))

    assert outcomes == ["already-consumed", "consumed"]


def test_pairing_store_revocation_blocks_later_consume(tmp_path: Path) -> None:
    store = PairingStore(tmp_path / "pairing.sqlite3")
    grant = issue_pairing_grant("hms-01", "https://bridge.example.test", now=NOW)
    store.create(grant.record)

    revoked = store.revoke(
        grant.record.pair_id,
        now=NOW + timedelta(seconds=1),
    )
    assert revoked.revoked_at == NOW + timedelta(seconds=1)

    with pytest.raises(PairingRevokedError, match="revoked"):
        store.consume(
            grant.record.pair_id,
            grant.token,
            instance_id="hms-01",
            now=NOW + timedelta(seconds=2),
        )
