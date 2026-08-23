from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os

import pytest

from hms_gpt_vps.agent_device_credential_store import (
    AGENT_DEVICE_CREDENTIAL_FILE_MAGIC,
    AgentDeviceCredentialConflictError,
    AgentDeviceCredentialIntegrityError,
    AgentDeviceCredentialStoreError,
    BridgeAgentDeviceCredentialStore,
    GuestAgentDeviceCredentialStore,
    guest_device_credential_path,
)
from hms_gpt_vps.agent_transport_protocol import AgentDeviceCredential


CREDENTIAL = AgentDeviceCredential(
    instance_id="hms-01",
    device_id="device-01",
    secret=b"S" * 32,
)


def bridge_protect(data: bytes) -> bytes:
    return b"B" + bytes(value ^ 0xA5 for value in data)


def guest_protect(data: bytes) -> bytes:
    return b"G" + bytes(value ^ 0x5A for value in data)


def bridge_unprotect(data: bytes) -> bytes:
    if not data.startswith(b"B"):
        raise ValueError("not bridge ciphertext")
    return bytes(value ^ 0xA5 for value in data[1:])


def guest_unprotect(data: bytes) -> bytes:
    if not data.startswith(b"G"):
        raise ValueError("not guest ciphertext")
    return bytes(value ^ 0x5A for value in data[1:])


def test_bridge_store_create_only_round_trip_hides_raw_secret(tmp_path) -> None:
    store = BridgeAgentDeviceCredentialStore(
        tmp_path / "bridge" / "device.dpapi",
        protector=bridge_protect,
        unprotector=bridge_unprotect,
    )
    saved = store.save_create_only(CREDENTIAL)
    loaded = store.load(
        expected_instance_id=CREDENTIAL.instance_id,
        expected_device_id=CREDENTIAL.device_id,
    )

    assert saved == CREDENTIAL
    assert loaded == CREDENTIAL
    raw = store.path.read_bytes()
    assert raw.startswith(AGENT_DEVICE_CREDENTIAL_FILE_MAGIC)
    assert CREDENTIAL.secret not in raw
    assert "SSSS" not in repr(loaded)


def test_guest_store_requires_preexisting_acl_managed_state_directory(tmp_path) -> None:
    path = tmp_path / "missing-state" / "agent-device-credential.dpapi"
    store = GuestAgentDeviceCredentialStore(
        path,
        protector=guest_protect,
        unprotector=guest_unprotect,
    )

    with pytest.raises(AgentDeviceCredentialStoreError, match="state directory must exist"):
        store.save_create_only(CREDENTIAL)
    assert not path.exists()


def test_guest_store_round_trip_in_existing_state_directory(tmp_path) -> None:
    state = tmp_path / "State"
    state.mkdir()
    path = guest_device_credential_path(state)
    store = GuestAgentDeviceCredentialStore(
        path,
        protector=guest_protect,
        unprotector=guest_unprotect,
    )

    store.save_create_only(CREDENTIAL)
    assert store.load(expected_instance_id="hms-01", expected_device_id="device-01") == CREDENTIAL
    assert CREDENTIAL.secret not in path.read_bytes()


def test_store_refuses_silent_secret_rotation_for_same_identity(tmp_path) -> None:
    store = BridgeAgentDeviceCredentialStore(
        tmp_path / "device.dpapi",
        protector=bridge_protect,
        unprotector=bridge_unprotect,
    )
    store.save_create_only(CREDENTIAL)
    changed = AgentDeviceCredential(
        instance_id=CREDENTIAL.instance_id,
        device_id=CREDENTIAL.device_id,
        secret=b"Z" * 32,
    )

    with pytest.raises(AgentDeviceCredentialConflictError, match="conflicts"):
        store.save_create_only(changed)
    assert store.load() == CREDENTIAL


def test_store_rejects_wrong_expected_instance_or_device(tmp_path) -> None:
    store = BridgeAgentDeviceCredentialStore(
        tmp_path / "device.dpapi",
        protector=bridge_protect,
        unprotector=bridge_unprotect,
    )
    store.save_create_only(CREDENTIAL)

    with pytest.raises(AgentDeviceCredentialIntegrityError, match="instance_id mismatch"):
        store.load(expected_instance_id="hms-02")
    with pytest.raises(AgentDeviceCredentialIntegrityError, match="device_id mismatch"):
        store.load(expected_device_id="device-02")


def test_protection_scope_is_bound_inside_encrypted_payload(tmp_path) -> None:
    state = tmp_path / "State"
    state.mkdir()
    guest_path = state / "device.dpapi"
    guest = GuestAgentDeviceCredentialStore(
        guest_path,
        protector=guest_protect,
        unprotector=guest_unprotect,
    )
    guest.save_create_only(CREDENTIAL)

    # Use the same unprotector deliberately: even if ciphertext can be opened,
    # the envelope role still prevents a guest/local-machine credential from
    # being accepted as a Bridge/current-user credential.
    wrong_role = BridgeAgentDeviceCredentialStore(
        guest_path,
        protector=guest_protect,
        unprotector=guest_unprotect,
    )
    with pytest.raises(AgentDeviceCredentialIntegrityError, match="scope mismatch"):
        wrong_role.load()


def test_existing_corrupt_file_is_never_replaced(tmp_path) -> None:
    path = tmp_path / "device.dpapi"
    corrupt = b"not-a-valid-device-credential"
    path.write_bytes(corrupt)
    store = BridgeAgentDeviceCredentialStore(
        path,
        protector=bridge_protect,
        unprotector=bridge_unprotect,
    )

    with pytest.raises(AgentDeviceCredentialIntegrityError, match="format marker"):
        store.save_create_only(CREDENTIAL)
    assert path.read_bytes() == corrupt


def test_concurrent_create_only_publication_returns_one_stable_credential(tmp_path) -> None:
    path = tmp_path / "bridge" / "device.dpapi"

    def save(_index: int) -> AgentDeviceCredential:
        store = BridgeAgentDeviceCredentialStore(
            path,
            protector=bridge_protect,
            unprotector=bridge_unprotect,
        )
        return store.save_create_only(CREDENTIAL)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(save, range(16)))

    assert all(result == CREDENTIAL for result in results)
    store = BridgeAgentDeviceCredentialStore(
        path,
        protector=bridge_protect,
        unprotector=bridge_unprotect,
    )
    assert store.load() == CREDENTIAL
    assert CREDENTIAL.secret not in path.read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="native DPAPI is Windows-only")
def test_native_windows_bridge_and_guest_dpapi_round_trip(tmp_path) -> None:
    credential = AgentDeviceCredential.generate("hms-01")

    bridge = BridgeAgentDeviceCredentialStore(tmp_path / "bridge" / "device.dpapi")
    bridge.save_create_only(credential)
    assert bridge.load(expected_instance_id="hms-01", expected_device_id=credential.device_id) == credential
    assert credential.secret not in bridge.path.read_bytes()

    state = tmp_path / "State"
    state.mkdir()
    guest = GuestAgentDeviceCredentialStore(guest_device_credential_path(state))
    guest.save_create_only(credential)
    assert guest.load(expected_instance_id="hms-01", expected_device_id=credential.device_id) == credential
    assert credential.secret not in guest.path.read_bytes()
