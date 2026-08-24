from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore


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
