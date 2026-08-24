from __future__ import annotations

import json
from pathlib import Path

import pytest

from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps import provision_state as provision_state_module


def test_provision_state_round_trip_remains_compatible(tmp_path: Path) -> None:
    store = ProvisionStateStore(tmp_path / "state" / "provision.json")
    saved = store.transition(
        instance_id="hms-01",
        state=ProvisionState.AGENT_INSTALLING,
        reason="test",
        increment_attempt=True,
    )

    loaded = store.load()
    assert loaded == saved
    assert loaded is not None
    assert loaded.attempt == 1
    assert loaded.state is ProvisionState.AGENT_INSTALLING


def test_provision_state_save_rejects_symlinked_parent_before_write(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    store = ProvisionStateStore(linked / "provision.json")
    with pytest.raises(ValueError, match="link or reparse"):
        store.transition(instance_id="hms-01", state=ProvisionState.IDLE)

    assert not (real / "provision.json").exists()


def test_provision_state_load_rejects_leaf_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real-state.json"
    ProvisionStateStore(real).transition(instance_id="hms-01", state=ProvisionState.IDLE)
    linked = tmp_path / "linked-state.json"
    try:
        linked.symlink_to(real)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(ValueError, match="link or reparse"):
        ProvisionStateStore(linked).load()


def test_provision_state_rejects_negative_attempt_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "provision.json"
    path.write_text(
        '{"schema_version":1,"instance_id":"hms-01","state":"idle","attempt":-1,'
        '"reason":null,"resume_state":null,"last_error":null}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="attempt is invalid"):
        ProvisionStateStore(path).load()


def test_provision_state_rejects_boolean_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "provision.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": True,
                "instance_id": "hms-01",
                "state": "idle",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="schema_version must be an integer"):
        ProvisionStateStore(path).load()


def test_provision_state_preserves_legacy_missing_optional_fields(tmp_path: Path) -> None:
    path = tmp_path / "provision.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "instance_id": "hms-legacy",
                "state": "agent_installing",
            }
        ),
        encoding="utf-8",
    )

    record = ProvisionStateStore(path).load()

    assert record is not None
    assert record.attempt == 0
    assert record.reason is None
    assert record.resume_state is None
    assert record.last_error is None


def test_provision_state_rejects_target_substitution_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "provision.json"
    store = ProvisionStateStore(path)
    store.transition(instance_id="hms-01", state=ProvisionState.AGENT_INSTALLING)
    original_bytes = path.read_bytes()
    displaced = tmp_path / "provision-opened.json"
    original_open = provision_state_module.os.open
    mutated = False

    def racing_open(target, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal mutated
        fd = original_open(target, flags, *args, **kwargs)
        if not mutated:
            mutated = True
            Path(target).replace(displaced)
            Path(target).write_bytes(original_bytes)
        return fd

    monkeypatch.setattr(provision_state_module.os, "open", racing_open)

    with pytest.raises(ValueError, match="authority changed during open"):
        store.load()

    assert path.exists()
    assert displaced.exists()
