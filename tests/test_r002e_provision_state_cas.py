from __future__ import annotations

from pathlib import Path
from threading import Event, Thread

import pytest

from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore


def test_transition_checked_serializes_stale_contender(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state" / "provision.json"
    first = ProvisionStateStore(path)
    second = ProvisionStateStore(path)
    first.transition(instance_id="hms-01", state=ProvisionState.IDLE)

    first_inside_save = Event()
    release_first = Event()
    second_done = Event()
    original_save = first._save_unlocked
    outcomes: dict[str, object] = {}

    def blocking_save(record):  # type: ignore[no-untyped-def]
        first_inside_save.set()
        assert release_first.wait(2)
        return original_save(record)

    monkeypatch.setattr(first, "_save_unlocked", blocking_save)

    def advance_first() -> None:
        outcomes["first"] = first.transition_checked(
            instance_id="hms-01",
            expected_state=ProvisionState.IDLE,
            state=ProvisionState.PREFLIGHT,
        )

    def advance_second() -> None:
        try:
            outcomes["second"] = second.transition_checked(
                instance_id="hms-01",
                expected_state=ProvisionState.IDLE,
                state=ProvisionState.FAILED,
            )
        except Exception as exc:  # noqa: BLE001 - assert exact fail-closed result below
            outcomes["second_error"] = exc
        finally:
            second_done.set()

    thread_first = Thread(target=advance_first)
    thread_first.start()
    assert first_inside_save.wait(2)

    thread_second = Thread(target=advance_second)
    thread_second.start()
    assert not second_done.wait(0.15), "second writer entered while CAS lock was held"

    release_first.set()
    thread_first.join(timeout=2)
    thread_second.join(timeout=2)
    assert not thread_first.is_alive()
    assert not thread_second.is_alive()

    error = outcomes.get("second_error")
    assert isinstance(error, ValueError)
    assert "found preflight" in str(error)
    assert path.exists()
    assert ProvisionStateStore(path).load().state is ProvisionState.PREFLIGHT  # type: ignore[union-attr]


def test_transition_checked_preserves_attempt_and_supports_atomic_increment(tmp_path: Path) -> None:
    store = ProvisionStateStore(tmp_path / "provision.json")
    first = store.transition(
        instance_id="hms-01",
        state=ProvisionState.IDLE,
        increment_attempt=True,
    )
    assert first.attempt == 1

    second = store.transition_checked(
        instance_id="hms-01",
        expected_state=ProvisionState.IDLE,
        state=ProvisionState.PREFLIGHT,
        increment_attempt=True,
    )
    assert second.attempt == 2


def test_transition_checked_does_not_double_load_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProvisionStateStore(tmp_path / "provision.json")
    store.transition(instance_id="hms-01", state=ProvisionState.IDLE)
    calls = 0
    original_load = store._load_unlocked

    def counted_load():  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return original_load()

    monkeypatch.setattr(store, "_load_unlocked", counted_load)
    result = store.transition_checked(
        instance_id="hms-01",
        expected_state=ProvisionState.IDLE,
        state=ProvisionState.PREFLIGHT,
    )

    assert result.state is ProvisionState.PREFLIGHT
    assert calls == 1
    assert store.lock_path.is_file()
