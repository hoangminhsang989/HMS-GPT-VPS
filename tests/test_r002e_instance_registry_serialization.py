from __future__ import annotations

from pathlib import Path
from threading import Event, Thread

import pytest

from hms_gpt_vps.instance_registry import InstanceRegistry, VMRecord


def _record(instance_id: str, *, vm_id: str | None = None) -> VMRecord:
    return VMRecord(
        instance_id=instance_id,
        vm_name=f"HMS-GPT-VPS-{instance_id}",
        backend="hyperv",
        phase="vm_created",
        workspace_path=r"C:\HMS-Workspace",
        vm_id=vm_id,
        switch_name="HMS-GPT-VPS-NAT",
        guest_ipv4=None,
    )


def test_registry_upsert_serializes_and_preserves_unrelated_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "instances.json"
    first = InstanceRegistry(path)
    second = InstanceRegistry(path)
    first_inside_write = Event()
    release_first = Event()
    second_done = Event()
    original_write = first._write_records_unlocked
    outcomes: dict[str, object] = {}

    def blocking_write(records):  # type: ignore[no-untyped-def]
        first_inside_write.set()
        assert release_first.wait(2)
        return original_write(records)

    monkeypatch.setattr(first, "_write_records_unlocked", blocking_write)

    def write_first() -> None:
        first.upsert(_record("hms-01", vm_id="11111111-2222-3333-4444-555555555555"))
        outcomes["first"] = True

    def write_second() -> None:
        try:
            second.upsert(_record("hms-02", vm_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
            outcomes["second"] = True
        finally:
            second_done.set()

    thread_first = Thread(target=write_first)
    thread_first.start()
    assert first_inside_write.wait(2)

    thread_second = Thread(target=write_second)
    thread_second.start()
    assert not second_done.wait(0.15), "second registry writer bypassed authority lock"

    release_first.set()
    thread_first.join(timeout=2)
    thread_second.join(timeout=2)
    assert not thread_first.is_alive()
    assert not thread_second.is_alive()
    assert outcomes == {"first": True, "second": True}

    records = InstanceRegistry(path).load()
    assert set(records) == {"hms-01", "hms-02"}


def test_registry_stale_contender_reloads_vm_id_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "instances.json"
    InstanceRegistry(path).upsert(_record("hms-01", vm_id=None))

    first = InstanceRegistry(path)
    second = InstanceRegistry(path)
    first_inside_write = Event()
    release_first = Event()
    second_done = Event()
    original_write = first._write_records_unlocked
    outcomes: dict[str, object] = {}

    def blocking_write(records):  # type: ignore[no-untyped-def]
        first_inside_write.set()
        assert release_first.wait(2)
        return original_write(records)

    monkeypatch.setattr(first, "_write_records_unlocked", blocking_write)

    def bind_first_identity() -> None:
        first.upsert(_record("hms-01", vm_id="11111111-2222-3333-4444-555555555555"))

    def bind_conflicting_identity() -> None:
        try:
            second.upsert(_record("hms-01", vm_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
        except Exception as exc:  # noqa: BLE001 - assert exact fail-closed outcome below
            outcomes["error"] = exc
        finally:
            second_done.set()

    thread_first = Thread(target=bind_first_identity)
    thread_first.start()
    assert first_inside_write.wait(2)

    thread_second = Thread(target=bind_conflicting_identity)
    thread_second.start()
    assert not second_done.wait(0.15), "conflicting VMId writer bypassed authority lock"

    release_first.set()
    thread_first.join(timeout=2)
    thread_second.join(timeout=2)
    assert not thread_first.is_alive()
    assert not thread_second.is_alive()

    error = outcomes.get("error")
    assert isinstance(error, ValueError)
    assert "different VMId" in str(error)
    persisted = InstanceRegistry(path).get("hms-01")
    assert persisted is not None
    assert persisted.vm_id == "11111111-2222-3333-4444-555555555555"
