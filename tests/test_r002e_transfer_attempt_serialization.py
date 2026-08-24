from __future__ import annotations

from pathlib import Path
from threading import Event, Thread

from hms_gpt_vps.agent_package_transfer_attempt import (
    AgentPackageTransferAttemptStore,
    AgentPackageTransferPhase,
)


class MemorySecretStore:
    def __init__(self) -> None:
        self.value: str | None = None

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("secret missing")
        return self.value

    def clear(self) -> None:
        self.value = None


def test_concurrent_begin_or_resume_converges_on_one_transfer_identity(tmp_path: Path) -> None:
    metadata = tmp_path / "transfer.json"
    secret = MemorySecretStore()
    first = AgentPackageTransferAttemptStore(metadata, secret)
    second = AgentPackageTransferAttemptStore(metadata, secret)
    outcomes: list[object] = []

    def begin(store: AgentPackageTransferAttemptStore) -> None:
        outcomes.append(
            store.begin_or_resume(
                instance_id="hms-01",
                vm_name="HMS-GPT-VPS-01",
                manifest_sha256="a" * 64,
            )
        )

    thread_first = Thread(target=begin, args=(first,))
    thread_second = Thread(target=begin, args=(second,))
    thread_first.start()
    thread_second.start()
    thread_first.join(timeout=2)
    thread_second.join(timeout=2)

    assert not thread_first.is_alive()
    assert not thread_second.is_alive()
    assert len(outcomes) == 2
    transfer_ids = {item.transfer_id for item in outcomes}  # type: ignore[union-attr]
    ownership_tokens = {item.ownership_token for item in outcomes}  # type: ignore[union-attr]
    assert len(transfer_ids) == 1
    assert len(ownership_tokens) == 1
    assert first.lock_path == second.lock_path


def test_stale_transfer_phase_contender_reloads_after_lock(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    metadata = tmp_path / "transfer.json"
    secret = MemorySecretStore()
    first = AgentPackageTransferAttemptStore(metadata, secret)
    second = AgentPackageTransferAttemptStore(metadata, secret)
    first.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="b" * 64,
    )
    first.bind_guest_service_interface_baseline(False)

    first_inside_write = Event()
    release_first = Event()
    second_done = Event()
    original_write = first._write_metadata
    outcomes: dict[str, object] = {}

    def blocking_write(attempt):  # type: ignore[no-untyped-def]
        first_inside_write.set()
        assert release_first.wait(2)
        return original_write(attempt)

    monkeypatch.setattr(first, "_write_metadata", blocking_write)

    def advance_first() -> None:
        outcomes["first"] = first.transition(
            AgentPackageTransferPhase.PLANNED,
            AgentPackageTransferPhase.TRANSFERRING,
        )

    def stale_second() -> None:
        try:
            outcomes["second"] = second.transition(
                AgentPackageTransferPhase.PLANNED,
                AgentPackageTransferPhase.PUBLISHED,
            )
        except Exception as exc:  # noqa: BLE001 - assert exact fail-closed result below
            outcomes["second_error"] = exc
        finally:
            second_done.set()

    thread_first = Thread(target=advance_first)
    thread_first.start()
    assert first_inside_write.wait(2)

    thread_second = Thread(target=stale_second)
    thread_second.start()
    assert not second_done.wait(0.15)

    release_first.set()
    thread_first.join(timeout=2)
    thread_second.join(timeout=2)
    assert not thread_first.is_alive()
    assert not thread_second.is_alive()

    error = outcomes.get("second_error")
    assert isinstance(error, ValueError)
    assert "found transferring" in str(error)
    final = first.load()
    assert final is not None
    assert final.phase is AgentPackageTransferPhase.TRANSFERRING
