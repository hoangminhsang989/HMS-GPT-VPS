from __future__ import annotations

import json
from pathlib import Path

import pytest

from hms_gpt_vps.instance_registry import InstanceRegistry, VMRecord
from hms_gpt_vps import instance_registry as registry_module


RECORD = VMRecord(
    instance_id="hms-01",
    vm_name="HMS-GPT-VPS-01",
    backend="hyperv",
    phase="vm_created",
    workspace_path=r"C:\HMS-Workspace",
    vm_id="11111111-2222-3333-4444-555555555555",
    switch_name="HMS-GPT-VPS-NAT",
    guest_ipv4="192.168.127.2",
)


def test_registry_rejects_parent_redirect_after_store_construction(tmp_path: Path) -> None:
    authority = tmp_path / "registry-authority"
    authority.mkdir()
    store = InstanceRegistry(authority / "instances.json")
    store.upsert(RECORD)

    preserved = tmp_path / "registry-preserved"
    redirected = tmp_path / "registry-redirected"
    redirected.mkdir()
    authority.rename(preserved)
    try:
        authority.symlink_to(redirected, target_is_directory=True)
    except OSError:
        preserved.rename(authority)
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(ValueError, match="authority path traverses"):
        store.load()


def test_registry_rejects_target_substitution_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "instances.json"
    store = InstanceRegistry(path)
    store.upsert(RECORD)
    original_bytes = path.read_bytes()
    displaced = tmp_path / "instances-opened.json"
    original_open = registry_module.os.open
    mutated = False

    def racing_open(target, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal mutated
        fd = original_open(target, flags, *args, **kwargs)
        if not mutated:
            mutated = True
            Path(target).replace(displaced)
            Path(target).write_bytes(original_bytes)
        return fd

    monkeypatch.setattr(registry_module.os, "open", racing_open)

    with pytest.raises(ValueError, match="authority changed during open"):
        store.load()

    assert path.exists()
    assert displaced.exists()


def test_registry_rejects_key_record_identity_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "instances.json"
    raw = {"other-instance": RECORD.__dict__}
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError, match="key does not match"):
        InstanceRegistry(path).load()


def test_registry_rejects_unknown_record_fields(tmp_path: Path) -> None:
    path = tmp_path / "instances.json"
    record = dict(RECORD.__dict__)
    record["unexpected"] = "must-not-be-accepted"
    path.write_text(json.dumps({RECORD.instance_id: record}), encoding="utf-8")

    with pytest.raises(ValueError, match="record fields are invalid"):
        InstanceRegistry(path).load()


@pytest.mark.parametrize(
    "vm_id",
    ["vm-id", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"],
)
def test_registry_rejects_noncanonical_vm_id(tmp_path: Path, vm_id: str) -> None:
    record = VMRecord(
        instance_id="hms-invalid",
        vm_name="HMS-GPT-VPS-INVALID",
        backend="hyperv",
        phase="vm_created",
        workspace_path=r"C:\HMS-Workspace",
        vm_id=vm_id,
    )
    with pytest.raises(ValueError, match="vm_id"):
        InstanceRegistry(tmp_path / "instances.json").upsert(record)


def test_registry_rejects_noncanonical_vm_id_from_persisted_json(tmp_path: Path) -> None:
    path = tmp_path / "instances.json"
    record = dict(RECORD.__dict__)
    record["vm_id"] = "vm-id"
    path.write_text(json.dumps({RECORD.instance_id: record}), encoding="utf-8")

    with pytest.raises(ValueError, match="vm_id"):
        InstanceRegistry(path).load()


def test_registry_preserves_legacy_missing_optional_fields(tmp_path: Path) -> None:
    path = tmp_path / "instances.json"
    legacy = {
        "instance_id": "hms-legacy",
        "vm_name": "HMS-GPT-VPS-LEGACY",
        "backend": "hyperv",
        "phase": "network_ready",
        "workspace_path": r"C:\HMS-Workspace",
    }
    path.write_text(json.dumps({"hms-legacy": legacy}), encoding="utf-8")

    record = InstanceRegistry(path).get("hms-legacy")

    assert record is not None
    assert record.vm_id is None
    assert record.switch_name is None
    assert record.guest_ipv4 is None
