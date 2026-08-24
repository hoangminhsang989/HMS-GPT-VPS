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
