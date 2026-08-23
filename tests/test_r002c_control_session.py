from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest

from hms_gpt_vps.control_session import (
    ControlSessionError,
    ControlSessionExpiredError,
    ControlSessionNotYetValidError,
    ControlSessionRevokedError,
    ControlSessionScopeError,
    ControlSessionTokenMismatchError,
    issue_control_session,
    verify_control_session,
)
from hms_gpt_vps.control_session_store import ControlSessionStore
from hms_gpt_vps.pairing import (
    PairingError,
    consume_pairing_record,
    issue_pairing_grant,
)


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)


def consumed_pairing(*, scopes: set[str] | None = None):
    grant = issue_pairing_grant(
        "hms-01",
        "https://bridge.example.test",
        scopes=scopes or {"workspace.read", "workspace.write", "git.status"},
        now=NOW,
    )
    record = consume_pairing_record(
        grant.record,
        grant.token,
        instance_id="hms-01",
        now=NOW + timedelta(seconds=1),
    )
    return record


def test_session_requires_consumed_pairing_and_cannot_backdate() -> None:
    pair_grant = issue_pairing_grant(
        "hms-01",
        "https://bridge.example.test",
        now=NOW,
    )
    with pytest.raises(PairingError, match="must be consumed"):
        issue_control_session(pair_grant.record, now=NOW + timedelta(seconds=1))

    consumed = consume_pairing_record(
        pair_grant.record,
        pair_grant.token,
        instance_id="hms-01",
        now=NOW + timedelta(seconds=2),
    )
    with pytest.raises(ControlSessionError, match="before pairing consumption"):
        issue_control_session(consumed, now=NOW + timedelta(seconds=1))


def test_session_token_is_redacted_and_scopes_cannot_escalate() -> None:
    pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))

    assert len(grant.token) >= 43
    assert grant.token not in repr(grant)
    assert grant.token not in repr(grant.record)
    assert grant.token not in str(grant.record.to_dict())
    assert grant.record.token_sha256 != grant.token

    with pytest.raises(ControlSessionScopeError, match="cannot exceed pairing scopes"):
        issue_control_session(
            pairing,
            now=NOW + timedelta(seconds=2),
            scopes={"workspace.read", "audit.read"},
        )


def test_session_verification_is_instance_scope_and_time_bound() -> None:
    pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))

    verify_control_session(
        grant.record,
        grant.token,
        instance_id="hms-01",
        required_scope="workspace.read",
        now=NOW + timedelta(seconds=3),
    )

    with pytest.raises(ControlSessionTokenMismatchError, match="instance mismatch"):
        verify_control_session(
            grant.record,
            grant.token,
            instance_id="other",
            required_scope="workspace.read",
            now=NOW + timedelta(seconds=3),
        )

    with pytest.raises(ControlSessionTokenMismatchError, match="token mismatch"):
        verify_control_session(
            grant.record,
            "wrong-token",
            instance_id="hms-01",
            required_scope="workspace.read",
            now=NOW + timedelta(seconds=3),
        )

    with pytest.raises(ControlSessionScopeError, match="does not grant scope"):
        verify_control_session(
            grant.record,
            grant.token,
            instance_id="hms-01",
            required_scope="audit.read",
            now=NOW + timedelta(seconds=3),
        )

    with pytest.raises(ControlSessionNotYetValidError, match="not yet valid"):
        verify_control_session(
            grant.record,
            grant.token,
            instance_id="hms-01",
            required_scope="workspace.read",
            now=NOW + timedelta(seconds=1),
        )

    with pytest.raises(ControlSessionExpiredError, match="expired"):
        verify_control_session(
            grant.record,
            grant.token,
            instance_id="hms-01",
            required_scope="workspace.read",
            now=grant.record.expires_at,
        )


def test_session_store_never_writes_raw_token(tmp_path: Path) -> None:
    pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))
    db_path = tmp_path / "sessions.sqlite3"
    store = ControlSessionStore(db_path)
    store.create(grant)

    assert grant.token.encode("utf-8") not in db_path.read_bytes()
    loaded = store.require(grant.record.session_id)
    assert loaded == grant.record


def test_rotation_revokes_old_token_preserves_family_and_increments_epoch(tmp_path: Path) -> None:
    pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))
    store = ControlSessionStore(tmp_path / "sessions.sqlite3")
    store.create(grant)

    rotation = store.rotate(
        grant.record.session_id,
        grant.token,
        instance_id="hms-01",
        now=NOW + timedelta(seconds=3),
        scopes={"workspace.read"},
    )

    assert rotation.previous.revoked_at == NOW + timedelta(seconds=3)
    assert rotation.previous.revocation_reason == "rotated"
    assert rotation.grant.record.family_id == grant.record.family_id
    assert rotation.grant.record.epoch == grant.record.epoch + 1
    assert rotation.grant.record.rotated_from == grant.record.session_id
    assert rotation.grant.record.scopes == ("workspace.read",)
    assert rotation.grant.token != grant.token

    with pytest.raises(ControlSessionRevokedError, match="revoked"):
        store.verify(
            grant.record.session_id,
            grant.token,
            instance_id="hms-01",
            required_scope="workspace.read",
            now=NOW + timedelta(seconds=4),
        )

    store.verify(
        rotation.grant.record.session_id,
        rotation.grant.token,
        instance_id="hms-01",
        required_scope="workspace.read",
        now=NOW + timedelta(seconds=4),
    )

    with pytest.raises(ControlSessionScopeError, match="cannot expand"):
        store.rotate(
            rotation.grant.record.session_id,
            rotation.grant.token,
            instance_id="hms-01",
            now=NOW + timedelta(seconds=5),
            scopes={"workspace.read", "workspace.write"},
        )


def test_concurrent_rotation_has_exactly_one_winner(tmp_path: Path) -> None:
    pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))
    store = ControlSessionStore(tmp_path / "sessions.sqlite3", timeout_seconds=10)
    store.create(grant)
    barrier = Barrier(2)

    def rotate_once() -> str:
        barrier.wait(timeout=5)
        try:
            store.rotate(
                grant.record.session_id,
                grant.token,
                instance_id="hms-01",
                now=NOW + timedelta(seconds=3),
            )
            return "rotated"
        except ControlSessionRevokedError:
            return "revoked"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(lambda _: rotate_once(), range(2)))

    assert outcomes == ["revoked", "rotated"]


def test_explicit_revocation_blocks_future_authorization(tmp_path: Path) -> None:
    pairing = consumed_pairing()
    grant = issue_control_session(pairing, now=NOW + timedelta(seconds=2))
    store = ControlSessionStore(tmp_path / "sessions.sqlite3")
    store.create(grant)

    revoked = store.revoke(
        grant.record.session_id,
        reason="operator_revoked",
        now=NOW + timedelta(seconds=3),
    )
    assert revoked.revocation_reason == "operator_revoked"

    with pytest.raises(ControlSessionRevokedError, match="revoked"):
        store.verify(
            grant.record.session_id,
            grant.token,
            instance_id="hms-01",
            required_scope="workspace.read",
            now=NOW + timedelta(seconds=4),
        )
