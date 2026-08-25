from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

import hms_gpt_vps.agent_command_store as agent_command_store_module
import hms_gpt_vps.idempotency_store as idempotency_store_module
from hms_gpt_vps.agent_command_store import (
    AgentCommandExpiredError,
    AgentCommandState,
    AgentCommandStore,
    AgentCommandStoreError,
)
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
    AgentCommandResult,
    AgentDeviceCredential,
    sign_bridge_command,
)
from hms_gpt_vps.idempotency_store import (
    IdempotencyError,
    IdempotencyInProgressError,
    IdempotencyStore,
)


NOW = datetime(2026, 8, 25, 5, 30, tzinfo=timezone.utc)


def credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id="hms-01",
        device_id="device-01",
        secret=b"S" * 32,
    )


def signed_command(
    *,
    request_id: str = "req-01",
    deadline_at: datetime | None = None,
):
    command = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id=request_id,
        instance_id="hms-01",
        action="workspace.read",
        params={"path": "hello.txt"},
        deadline_at=deadline_at or NOW + timedelta(minutes=5),
    )
    return sign_bridge_command(credential(), command)


@pytest.mark.parametrize(
    "timeout",
    [True, 0, -1, float("inf"), 31],
)
def test_bridge_authority_stores_reject_invalid_timeout(
    tmp_path: Path,
    timeout: object,
) -> None:
    with pytest.raises(ValueError, match="between 0 and 30"):
        AgentCommandStore(
            tmp_path / "commands.sqlite3",
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="between 0 and 30"):
        IdempotencyStore(
            tmp_path / "idempotency.sqlite3",
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


def test_agent_command_store_preserves_missing_parent_fail_closed_rule(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "missing"
    with pytest.raises(AgentCommandStoreError, match="parent must already exist"):
        AgentCommandStore(parent / "commands.sqlite3")
    assert parent.exists() is False


@pytest.mark.skipif(
    not hasattr(os, "symlink"),
    reason="platform does not support symbolic links",
)
def test_bridge_authority_stores_reject_symlink_parent(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    redirected = tmp_path / "redirected"
    try:
        redirected.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic link creation is unavailable")

    with pytest.raises(AgentCommandStoreError, match="link or reparse"):
        AgentCommandStore(redirected / "commands.sqlite3")
    with pytest.raises(IdempotencyError, match="link or reparse"):
        IdempotencyStore(redirected / "idempotency.sqlite3")


def _replace_database(path: Path, replacement: Path) -> None:
    with sqlite3.connect(replacement):
        pass
    os.replace(replacement, path)


def test_agent_command_store_rejects_main_database_replacement(
    tmp_path: Path,
) -> None:
    store = AgentCommandStore(tmp_path / "commands.sqlite3")
    store.enqueue(signed_command(), now=NOW)
    _replace_database(store.path, tmp_path / "replacement.sqlite3")

    with pytest.raises(AgentCommandStoreError, match="startup authority"):
        store.get_status("hms-01", "req-01")


def test_idempotency_store_rejects_main_database_replacement(
    tmp_path: Path,
) -> None:
    store = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    store.claim("session-01", "req-01", "a" * 64, now=NOW)
    _replace_database(store.path, tmp_path / "replacement.sqlite3")

    with pytest.raises(IdempotencyError, match="startup authority"):
        store.claim("session-01", "req-01", "a" * 64, now=NOW)


class _ExplodingPragmaConnection:
    def __init__(self) -> None:
        self.row_factory: object | None = None
        self.closed = False

    def execute(self, statement: str, *args: object) -> object:
        raise RuntimeError(f"forced setup failure: {statement}")

    def close(self) -> None:
        self.closed = True


def test_agent_command_store_closes_connection_when_setup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _ExplodingPragmaConnection()
    monkeypatch.setattr(
        agent_command_store_module.sqlite3,
        "connect",
        lambda *args, **kwargs: connection,
    )

    with pytest.raises(RuntimeError, match="forced setup failure"):
        AgentCommandStore(tmp_path / "commands-cleanup.sqlite3")
    assert connection.closed is True


def test_idempotency_store_closes_connection_when_setup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _ExplodingPragmaConnection()
    monkeypatch.setattr(
        idempotency_store_module.sqlite3,
        "connect",
        lambda *args, **kwargs: connection,
    )

    with pytest.raises(RuntimeError, match="forced setup failure"):
        IdempotencyStore(tmp_path / "idempotency-cleanup.sqlite3")
    assert connection.closed is True


def test_agent_command_store_rejects_noncanonical_stored_hash(
    tmp_path: Path,
) -> None:
    store = AgentCommandStore(tmp_path / "commands.sqlite3")
    store.enqueue(signed_command(), now=NOW)

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            UPDATE agent_commands
            SET command_sha256 = upper(command_sha256)
            WHERE instance_id = ? AND request_id = ?
            """,
            ("hms-01", "req-01"),
        )

    with pytest.raises(AgentCommandStoreError, match="canonical lowercase"):
        store.get_status("hms-01", "req-01")


def test_agent_command_store_rejects_duplicate_stored_json_even_with_matching_hash(
    tmp_path: Path,
) -> None:
    store = AgentCommandStore(tmp_path / "commands.sqlite3")
    store.enqueue(signed_command(), now=NOW)

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            """
            SELECT command_json FROM agent_commands
            WHERE instance_id = ? AND request_id = ?
            """,
            ("hms-01", "req-01"),
        ).fetchone()
        assert row is not None
        original = json.loads(row[0])
        command_json = json.dumps(
            original["command"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        signature_json = json.dumps(original["signature"])
        duplicate = (
            '{"command":'
            + command_json
            + ',"signature":'
            + signature_json
            + ',"signature":'
            + signature_json
            + "}"
        )
        digest = hashlib.sha256(duplicate.encode("utf-8")).hexdigest()
        connection.execute(
            """
            UPDATE agent_commands
            SET command_json = ?, command_sha256 = ?
            WHERE instance_id = ? AND request_id = ?
            """,
            (duplicate, digest, "hms-01", "req-01"),
        )

    with pytest.raises(AgentCommandStoreError, match="duplicate JSON key"):
        store.get_status("hms-01", "req-01")


@pytest.mark.parametrize("bad_deadline", ["nan", float("inf")])
def test_agent_command_store_rejects_nonfinite_or_coerced_deadline(
    tmp_path: Path,
    bad_deadline: object,
) -> None:
    store = AgentCommandStore(tmp_path / "commands.sqlite3")
    store.enqueue(signed_command(), now=NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            UPDATE agent_commands
            SET deadline_unix = ?
            WHERE instance_id = ? AND request_id = ?
            """,
            (bad_deadline, "hms-01", "req-01"),
        )

    with pytest.raises(AgentCommandStoreError, match="finite number"):
        store.get_status("hms-01", "req-01")


def test_agent_command_complete_after_deadline_persists_expired_state(
    tmp_path: Path,
) -> None:
    store = AgentCommandStore(tmp_path / "commands.sqlite3")
    store.enqueue(
        signed_command(deadline_at=NOW + timedelta(seconds=1)),
        now=NOW,
    )
    result = AgentCommandResult(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-01",
        instance_id="hms-01",
        outcome="ok",
        response={"ok": True},
        completed_at=NOW + timedelta(seconds=2),
    )

    with pytest.raises(AgentCommandExpiredError, match="after command expiration"):
        store.complete(result, now=NOW + timedelta(seconds=2))

    status = store.get_status("hms-01", "req-01")
    assert status is not None
    assert status.state is AgentCommandState.EXPIRED
    assert status.result is None


def test_idempotency_store_rejects_noncanonical_request_hash_in_database(
    tmp_path: Path,
) -> None:
    store = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    store.claim("session-01", "req-01", "a" * 64, now=NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            UPDATE idempotency_records
            SET request_sha256 = upper(request_sha256)
            WHERE session_id = ? AND request_id = ?
            """,
            ("session-01", "req-01"),
        )

    with pytest.raises(IdempotencyError, match="canonical lowercase"):
        store.claim("session-01", "req-01", "a" * 64, now=NOW)


def test_idempotency_store_rejects_duplicate_cached_json_with_matching_hash(
    tmp_path: Path,
) -> None:
    store = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    request_hash = "b" * 64
    store.claim("session-01", "req-01", request_hash, now=NOW)
    store.complete(
        "session-01",
        "req-01",
        request_hash,
        {"ok": True},
        now=NOW + timedelta(seconds=1),
    )

    duplicate = '{"ok":true,"ok":true}'
    digest = hashlib.sha256(duplicate.encode("utf-8")).hexdigest()
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            UPDATE idempotency_records
            SET response_json = ?, response_sha256 = ?
            WHERE session_id = ? AND request_id = ?
            """,
            (duplicate, digest, "session-01", "req-01"),
        )

    with pytest.raises(IdempotencyError, match="duplicate JSON key"):
        store.claim(
            "session-01",
            "req-01",
            request_hash,
            now=NOW + timedelta(seconds=2),
        )


def test_idempotency_store_rejects_nonstring_state_and_preserves_unresolved_semantics(
    tmp_path: Path,
) -> None:
    store = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    request_hash = "c" * 64
    store.claim("session-01", "req-01", request_hash, now=NOW)
    with pytest.raises(IdempotencyInProgressError, match="automatic replay is blocked"):
        store.claim(
            "session-01",
            "req-01",
            request_hash,
            now=NOW + timedelta(seconds=1),
        )

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            UPDATE idempotency_records
            SET state = 1
            WHERE session_id = ? AND request_id = ?
            """,
            ("session-01", "req-01"),
        )
    with pytest.raises(IdempotencyError, match="non-empty string"):
        store.claim(
            "session-01",
            "req-01",
            request_hash,
            now=NOW + timedelta(seconds=2),
        )
