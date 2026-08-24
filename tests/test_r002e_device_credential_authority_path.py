from __future__ import annotations

import json
from pathlib import Path

import pytest

from hms_gpt_vps.agent_device_credential_store import (
    AGENT_DEVICE_CREDENTIAL_FILE_MAGIC,
    AgentDeviceCredentialIntegrityError,
    BridgeAgentDeviceCredentialStore,
)
from hms_gpt_vps.agent_transport_protocol import AgentDeviceCredential


CREDENTIAL = AgentDeviceCredential(
    instance_id="hms-01",
    device_id="device-01",
    secret=b"S" * 32,
)


def _protect(data: bytes) -> bytes:
    return b"B" + data


def _unprotect(data: bytes) -> bytes:
    if not data.startswith(b"B"):
        raise ValueError("invalid test ciphertext")
    return data[1:]


def test_bridge_credential_store_rejects_parent_redirect_after_construction(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "bridge-authority"
    authority.mkdir()
    path = authority / "device.dpapi"
    store = BridgeAgentDeviceCredentialStore(
        path,
        protector=_protect,
        unprotector=_unprotect,
    )
    store.save_create_only(CREDENTIAL)

    preserved = tmp_path / "bridge-authority-preserved"
    redirected = tmp_path / "bridge-authority-redirected"
    redirected.mkdir()
    authority.rename(preserved)
    try:
        authority.symlink_to(redirected, target_is_directory=True)
    except OSError:
        preserved.rename(authority)
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(
        AgentDeviceCredentialIntegrityError,
        match="authority path traverses",
    ):
        store.load(expected_instance_id="hms-01")


def test_bridge_credential_store_refuses_write_through_redirected_parent(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "bridge-authority"
    authority.mkdir()
    store = BridgeAgentDeviceCredentialStore(
        authority / "device.dpapi",
        protector=_protect,
        unprotector=_unprotect,
    )

    preserved = tmp_path / "bridge-authority-preserved"
    redirected = tmp_path / "bridge-authority-redirected"
    redirected.mkdir()
    authority.rename(preserved)
    try:
        authority.symlink_to(redirected, target_is_directory=True)
    except OSError:
        preserved.rename(authority)
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(
        AgentDeviceCredentialIntegrityError,
        match="authority path traverses",
    ):
        store.save_create_only(CREDENTIAL)
    assert not (redirected / "device.dpapi").exists()


def test_device_credential_schema_rejects_boolean_true_as_version_one(
    tmp_path: Path,
) -> None:
    path = tmp_path / "device.dpapi"
    payload = {
        "schema_version": True,
        "protection_scope": "current-user",
        "instance_id": CREDENTIAL.instance_id,
        "device_id": CREDENTIAL.device_id,
        "secret_b64": "U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M=",
    }
    path.write_bytes(
        AGENT_DEVICE_CREDENTIAL_FILE_MAGIC
        + b"B"
        + json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    store = BridgeAgentDeviceCredentialStore(
        path,
        protector=_protect,
        unprotector=_unprotect,
    )

    with pytest.raises(AgentDeviceCredentialIntegrityError, match="unsupported.*schema"):
        store.load()
