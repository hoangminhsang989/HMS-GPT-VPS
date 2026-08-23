from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json

import pytest

import hms_gpt_vps.agent_device_enrollment as enrollment
from hms_gpt_vps.agent_device_credential_store import (
    AgentDeviceCredentialIntegrityError,
    BridgeAgentDeviceCredentialStore,
)
from hms_gpt_vps.agent_device_enrollment import (
    AgentDeviceEnrollmentConfig,
    AgentDeviceEnrollmentError,
    _build_enrollment_payload,
    build_guest_device_enrollment_script,
    enroll_agent_device,
    load_or_create_bridge_credential,
)
from hms_gpt_vps.agent_transport_protocol import AgentDeviceCredential
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential


def protect(data: bytes) -> bytes:
    return b"P" + bytes(value ^ 0x37 for value in data)


def unprotect(data: bytes) -> bytes:
    if not data.startswith(b"P"):
        raise ValueError("bad ciphertext")
    return bytes(value ^ 0x37 for value in data[1:])


def bridge_store(path) -> BridgeAgentDeviceCredentialStore:
    return BridgeAgentDeviceCredentialStore(
        path,
        protector=protect,
        unprotector=unprotect,
    )


def test_load_or_create_bridge_credential_is_stable_across_retries(tmp_path) -> None:
    store = bridge_store(tmp_path / "bridge" / "device.dpapi")

    first = load_or_create_bridge_credential(store, "hms-01")
    second = load_or_create_bridge_credential(store, "hms-01")

    assert first == second
    assert first.instance_id == "hms-01"
    assert store.load(expected_instance_id="hms-01") == first
    assert first.secret not in store.path.read_bytes()


def test_load_or_create_bridge_credential_converges_under_concurrency(tmp_path) -> None:
    path = tmp_path / "bridge" / "device.dpapi"

    def create(_index: int) -> AgentDeviceCredential:
        return load_or_create_bridge_credential(bridge_store(path), "hms-01")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(create, range(16)))

    assert len({result.device_id for result in results}) == 1
    assert len({result.secret for result in results}) == 1
    persisted = bridge_store(path).load(expected_instance_id="hms-01")
    assert all(result == persisted for result in results)


def test_load_or_create_refuses_existing_wrong_instance(tmp_path) -> None:
    store = bridge_store(tmp_path / "device.dpapi")
    store.save_create_only(AgentDeviceCredential.generate("hms-01"))

    with pytest.raises(AgentDeviceCredentialIntegrityError, match="instance_id mismatch"):
        load_or_create_bridge_credential(store, "hms-02")


def test_enrollment_payload_is_bounded_and_contains_exact_credential() -> None:
    credential = AgentDeviceCredential(
        instance_id="hms-01",
        device_id="device-01",
        secret=b"S" * 32,
    )
    payload = json.loads(_build_enrollment_payload(credential).decode("utf-8"))

    assert payload == {
        "schema_version": 1,
        "instance_id": "hms-01",
        "device_id": "device-01",
        "secret_b64": base64.b64encode(b"S" * 32).decode("ascii"),
    }


def test_guest_enrollment_script_is_secret_free_machine_dpapi_create_only() -> None:
    secret = "THIS-MUST-NOT-APPEAR"
    script = build_guest_device_enrollment_script(
        AgentDeviceEnrollmentConfig(instance_id="hms-01")
    )

    assert secret not in script
    assert "param([Parameter(Mandatory=$true)][string]$PayloadB64)" in script
    assert "DataProtectionScope]::LocalMachine" in script
    assert "ProtectedData]::Protect" in script
    assert "ProtectedData]::Unprotect" in script
    assert "HMS-ADC-V1" in script
    assert "[System.IO.File]::Move($tempPath, $credentialPath)" in script
    assert "'/inheritance:r'" in script
    assert "*S-1-5-18:(OI)(CI)F" in script
    assert "*S-1-5-32-544:(OI)(CI)F" in script
    assert "Users:(" not in script
    assert "Everyone:(" not in script


def test_enroll_agent_device_sends_secret_only_as_env_payload(monkeypatch, tmp_path) -> None:
    store = bridge_store(tmp_path / "bridge" / "device.dpapi")
    bootstrap = PowerShellDirectCredential(username="hmsbootstrap", password="B" * 32)
    config = AgentDeviceEnrollmentConfig(instance_id="hms-01")
    captured: dict[str, object] = {}

    def fake_run(
        vm_name: str,
        credential: PowerShellDirectCredential,
        guest_script: str,
        *,
        timeout_seconds: int,
        secret_payload: bytes | None = None,
    ) -> dict[str, object]:
        assert vm_name == "HMS-GPT-VPS-01"
        assert credential is bootstrap
        assert timeout_seconds == 77
        assert secret_payload is not None
        payload = json.loads(secret_payload.decode("utf-8"))
        raw_secret = base64.b64decode(payload["secret_b64"])
        assert raw_secret not in guest_script.encode("utf-8")
        assert payload["instance_id"] == "hms-01"
        captured["payload"] = payload
        return {
            "ready": True,
            "created": True,
            "instance_id": payload["instance_id"],
            "device_id": payload["device_id"],
            "credential_path": r"C:\ProgramData\HMS-GPT-VPS\State\agent-device-credential.dpapi",
        }

    monkeypatch.setattr(enrollment, "run_vm_powershell_json", fake_run)
    result = enroll_agent_device(
        "HMS-GPT-VPS-01",
        bootstrap,
        store,
        config,
        timeout_seconds=77,
    )

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert result.instance_id == "hms-01"
    assert result.device_id == payload["device_id"]
    assert "secret" not in repr(result).lower()
    assert store.load(expected_instance_id="hms-01", expected_device_id=result.device_id).device_id == result.device_id


def test_enroll_agent_device_rejects_guest_identity_mismatch(monkeypatch, tmp_path) -> None:
    store = bridge_store(tmp_path / "bridge" / "device.dpapi")

    def fake_run(*_args, **_kwargs) -> dict[str, object]:
        return {
            "ready": True,
            "instance_id": "hms-01",
            "device_id": "different-device",
            "credential_path": r"C:\ProgramData\HMS-GPT-VPS\State\agent-device-credential.dpapi",
        }

    monkeypatch.setattr(enrollment, "run_vm_powershell_json", fake_run)
    with pytest.raises(AgentDeviceEnrollmentError, match="wrong device_id"):
        enroll_agent_device(
            "HMS-GPT-VPS-01",
            PowerShellDirectCredential(username="hmsbootstrap", password="B" * 32),
            store,
            AgentDeviceEnrollmentConfig(instance_id="hms-01"),
        )


def test_enrollment_config_rejects_relative_guest_state_path() -> None:
    with pytest.raises(ValueError, match="absolute Windows path"):
        AgentDeviceEnrollmentConfig(
            instance_id="hms-01",
            guest_state_path=r"relative\State",
        ).validate()
