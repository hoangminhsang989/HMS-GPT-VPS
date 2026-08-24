from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from hms_gpt_vps.agent_package_transfer_attempt import (
    AGENT_PACKAGE_TRANSFER_ATTEMPT_SCHEMA_VERSION,
    AgentPackageTransferAttemptStore,
    AgentPackageTransferPhase,
)
from hms_gpt_vps import agent_package_transfer_attempt as attempt_module


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


def publish_attempt(store: AgentPackageTransferAttemptStore) -> None:
    store.bind_guest_service_interface_baseline(False)
    store.transition(
        AgentPackageTransferPhase.PLANNED,
        AgentPackageTransferPhase.TRANSFERRING,
    )
    store.transition(
        AgentPackageTransferPhase.TRANSFERRING,
        AgentPackageTransferPhase.PUBLISHED,
    )


def test_transfer_attempt_metadata_never_contains_ownership_token(tmp_path: Path) -> None:
    store, secret_store = make_store(tmp_path)
    attempt = store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="a" * 64,
    )

    raw_text = (tmp_path / "transfer.json").read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    assert raw["schema_version"] == AGENT_PACKAGE_TRANSFER_ATTEMPT_SCHEMA_VERSION
    assert "ownership_token" not in raw
    assert raw["guest_service_interface_was_enabled"] is None
    assert raw["ownership_token_sha256"] == hashlib.sha256(
        attempt.ownership_token.encode("ascii")
    ).hexdigest()
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


def test_transfer_attempt_rejects_valid_but_mismatched_secret_half(tmp_path: Path) -> None:
    store, secret_store = make_store(tmp_path)
    attempt = store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="8" * 64,
    )
    replacement = "0" * 48
    if replacement == attempt.ownership_token:
        replacement = "1" * 48
    secret_store.value = replacement

    with pytest.raises(ValueError, match="ownership token does not match metadata"):
        store.load()


def test_transfer_attempt_store_rejects_parent_redirect_after_construction(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    redirected_target = tmp_path / "redirected-target"
    redirected_target.mkdir()
    preserved_authority = tmp_path / "preserved-authority"
    secret_store = MemorySecretStore()
    store = AgentPackageTransferAttemptStore(authority / "transfer.json", secret_store)

    authority.rename(preserved_authority)
    try:
        authority.symlink_to(redirected_target, target_is_directory=True)
    except OSError:
        preserved_authority.rename(authority)
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(ValueError, match="metadata authority path traverses"):
        store.begin_or_resume(
            instance_id="hms-01",
            vm_name="HMS-GPT-VPS-01",
            manifest_sha256="9" * 64,
        )

    assert not (redirected_target / "transfer.json").exists()
    assert secret_store.value is None


def test_transfer_metadata_read_rejects_target_substitution_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _ = make_store(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="7" * 64,
    )
    path = tmp_path / "transfer.json"
    original = path.read_bytes()
    displaced = tmp_path / "transfer-opened.json"
    original_open = attempt_module.os.open
    mutated = False

    def racing_open(target, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal mutated
        fd = original_open(target, flags, *args, **kwargs)
        if not mutated and not (flags & os.O_RDWR):
            mutated = True
            Path(target).replace(displaced)
            Path(target).write_bytes(original)
        return fd

    monkeypatch.setattr(attempt_module.os, "open", racing_open)

    with pytest.raises(ValueError, match="authority changed during open"):
        store.load()

    assert path.exists()
    assert displaced.exists()


def test_transfer_metadata_schema_requires_native_integer(tmp_path: Path) -> None:
    store, _ = make_store(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="6" * 64,
    )
    path = tmp_path / "transfer.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["schema_version"] = True
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported Agent package transfer attempt schema"):
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

    publish_attempt(store)
    store.clear_published()

    metadata = tmp_path / "transfer.json"
    assert metadata.is_file()
    assert metadata.stat().st_size == 0
    assert store.load() is None
    assert secret_store.value is None


def test_published_clear_rejects_metadata_substitution_before_tombstone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, secret_store = make_store(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="5" * 64,
    )
    publish_attempt(store)
    path = tmp_path / "transfer.json"
    published_bytes = path.read_bytes()
    displaced = tmp_path / "published-opened.json"
    original_open = attempt_module.os.open
    mutated = False

    def racing_open(target, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal mutated
        fd = original_open(target, flags, *args, **kwargs)
        if not mutated and (flags & os.O_RDWR):
            mutated = True
            Path(target).replace(displaced)
            Path(target).write_bytes(published_bytes)
        return fd

    monkeypatch.setattr(attempt_module.os, "open", racing_open)

    with pytest.raises(ValueError, match="authority changed before clear"):
        store.clear_published()

    assert path.read_bytes() == published_bytes
    assert displaced.read_bytes() == published_bytes
    assert secret_store.value is not None
