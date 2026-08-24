from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def make_store(tmp_path: Path) -> tuple[AgentPackageTransferAttemptStore, MemorySecretStore]:
    secrets = MemorySecretStore()
    return AgentPackageTransferAttemptStore(tmp_path / "transfer.json", secrets), secrets


def test_transfer_attempt_metadata_never_contains_ownership_token(tmp_path: Path) -> None:
    store, secret_store = make_store(tmp_path)
    attempt = store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="a" * 64,
    )

    raw_text = (tmp_path / "transfer.json").read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    assert "ownership_token" not in raw
    assert raw["guest_service_interface_was_enabled"] is None
    assert attempt.ownership_token not in raw_text
    assert secret_store.value == attempt.ownership_token
    assert attempt.ownership_token not in repr(attempt)


def test_transfer_attempt_resume_reuses_exact_id_token_and_integration_baseline(
    tmp_path: Path,
) -> None:
    store, _ = make_store(tmp_path)
    first = store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="b" * 64,
    )
    bound = store.bind_guest_service_interface_baseline(False)
    assert bound.transfer_id == first.transfer_id
    store.transition(
        AgentPackageTransferPhase.PLANNED,
        AgentPackageTransferPhase.TRANSFERRING,
    )
    resumed = store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="b" * 64,
    )

    assert resumed.transfer_id == first.transfer_id
    assert resumed.ownership_token == first.ownership_token
    assert resumed.guest_service_interface_was_enabled is False
    assert resumed.phase is AgentPackageTransferPhase.TRANSFERRING


def test_transfer_cannot_mutate_before_integration_baseline_is_persisted(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="1" * 64,
    )

    with pytest.raises(ValueError, match="baseline must be persisted"):
        store.transition(
            AgentPackageTransferPhase.PLANNED,
            AgentPackageTransferPhase.TRANSFERRING,
        )


def test_integration_baseline_cannot_change_after_transfer_mutation(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="2" * 64,
    )
    store.bind_guest_service_interface_baseline(False)
    store.transition(
        AgentPackageTransferPhase.PLANNED,
        AgentPackageTransferPhase.TRANSFERRING,
    )

    with pytest.raises(ValueError, match="cannot change"):
        store.bind_guest_service_interface_baseline(True)


def test_transfer_attempt_mismatch_fails_closed(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="c" * 64,
    )

    with pytest.raises(ValueError, match="another package manifest"):
        store.begin_or_resume(
            instance_id="hms-01",
            vm_name="HMS-GPT-VPS-01",
            manifest_sha256="d" * 64,
        )
    with pytest.raises(ValueError, match="another VM"):
        store.begin_or_resume(
            instance_id="hms-01",
            vm_name="OTHER-VM",
            manifest_sha256="c" * 64,
        )


def test_transfer_attempt_missing_secret_fails_closed(tmp_path: Path) -> None:
    store, secret_store = make_store(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="e" * 64,
    )
    secret_store.clear()

    with pytest.raises(ValueError, match="ownership token is missing"):
        store.load()


def test_only_published_attempt_can_be_cleared(tmp_path: Path) -> None:
    store, secret_store = make_store(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="only a published"):
        store.clear_published()

    store.bind_guest_service_interface_baseline(False)
    store.transition(
        AgentPackageTransferPhase.PLANNED,
        AgentPackageTransferPhase.TRANSFERRING,
    )
    store.transition(
        AgentPackageTransferPhase.TRANSFERRING,
        AgentPackageTransferPhase.PUBLISHED,
    )
    store.clear_published()

    assert not (tmp_path / "transfer.json").exists()
    assert secret_store.value is None
