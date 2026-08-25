from __future__ import annotations

from pathlib import PureWindowsPath

import pytest

import hms_gpt_vps.agent_device_enrollment as enrollment_module
from hms_gpt_vps.agent_device_credential_store import GUEST_DEVICE_CREDENTIAL_FILENAME
from hms_gpt_vps.agent_device_enrollment import (
    AgentDeviceEnrollmentConfig,
    AgentDeviceEnrollmentError,
    build_guest_device_enrollment_script,
    enroll_agent_device,
)
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_DEVICE_SECRET_BYTES,
    AgentDeviceCredential,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential


INSTANCE_ID = "hms-01"
DEVICE_ID = "device-01"
VM_NAME = "HMS-GPT-VPS-01"


def _credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id=INSTANCE_ID,
        device_id=DEVICE_ID,
        secret=b"x" * AGENT_DEVICE_SECRET_BYTES,
    )


def _config() -> AgentDeviceEnrollmentConfig:
    return AgentDeviceEnrollmentConfig(instance_id=INSTANCE_ID)


def _expected_path(config: AgentDeviceEnrollmentConfig) -> str:
    return str(PureWindowsPath(config.guest_state_path) / GUEST_DEVICE_CREDENTIAL_FILENAME)


def _invoke(
    monkeypatch: pytest.MonkeyPatch,
    guest_result: object,
    *,
    timeout_seconds: object = 120,
):
    credential = _credential()
    monkeypatch.setattr(
        enrollment_module,
        "load_or_create_bridge_credential",
        lambda *args, **kwargs: credential,
    )
    monkeypatch.setattr(
        enrollment_module,
        "run_vm_powershell_json",
        lambda *args, **kwargs: guest_result,
    )
    return enroll_agent_device(
        VM_NAME,
        PowerShellDirectCredential("Administrator", "password"),
        object(),  # type: ignore[arg-type]
        _config(),
        timeout_seconds=timeout_seconds,  # type: ignore[arg-type]
    )


def _valid_guest_result() -> dict[str, object]:
    config = _config()
    return {
        "ready": True,
        "created": False,
        "instance_id": INSTANCE_ID,
        "device_id": DEVICE_ID,
        "credential_path": _expected_path(config),
    }


def test_enrollment_accepts_exact_result(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _invoke(monkeypatch, _valid_guest_result())
    assert result.instance_id == INSTANCE_ID
    assert result.device_id == DEVICE_ID
    assert result.credential_path == _expected_path(_config())


@pytest.mark.parametrize("bad_ready", ["false", 1, 0, None])
def test_enrollment_rejects_coerced_ready(
    monkeypatch: pytest.MonkeyPatch,
    bad_ready: object,
) -> None:
    payload = _valid_guest_result()
    payload["ready"] = bad_ready
    with pytest.raises(AgentDeviceEnrollmentError, match="postcondition"):
        _invoke(monkeypatch, payload)


@pytest.mark.parametrize("bad_created", ["false", 1, 0, None])
def test_enrollment_rejects_coerced_created(
    monkeypatch: pytest.MonkeyPatch,
    bad_created: object,
) -> None:
    payload = _valid_guest_result()
    payload["created"] = bad_created
    with pytest.raises(AgentDeviceEnrollmentError, match="created evidence"):
        _invoke(monkeypatch, payload)


def test_enrollment_rejects_result_schema_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _valid_guest_result()
    payload["extra"] = True
    with pytest.raises(AgentDeviceEnrollmentError, match="schema"):
        _invoke(monkeypatch, payload)


@pytest.mark.parametrize(
    ("key", "value", "match"),
    [
        ("instance_id", 123, "instance_id"),
        ("device_id", 123, "device_id"),
        ("credential_path", 123, "credential path"),
    ],
)
def test_enrollment_rejects_non_string_identity_evidence(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: object,
    match: str,
) -> None:
    payload = _valid_guest_result()
    payload[key] = value
    with pytest.raises(AgentDeviceEnrollmentError, match=match):
        _invoke(monkeypatch, payload)


def test_enrollment_binds_exact_managed_credential_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _valid_guest_result()
    payload["credential_path"] = r"C:\Temp\agent-device.credential"
    with pytest.raises(AgentDeviceEnrollmentError, match="outside managed authority"):
        _invoke(monkeypatch, payload)


def test_enrollment_rejects_bool_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="timeout_seconds must be an integer"):
        _invoke(monkeypatch, _valid_guest_result(), timeout_seconds=True)


def test_enrollment_rejects_out_of_range_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="between 1 and 600"):
        _invoke(monkeypatch, _valid_guest_result(), timeout_seconds=0)


def test_enrollment_script_uses_exact_json_type_guards() -> None:
    script = build_guest_device_enrollment_script(_config())
    assert "Test-HmsJsonInteger $stored.schema_version" in script
    assert "Test-HmsJsonInteger $payload.schema_version" in script
    assert "Assert-HmsJsonString $stored.instance_id" in script
    assert "Assert-HmsJsonString $payload.instance_id" in script
    assert "[int]$stored.schema_version" not in script
    assert "[int]$payload.schema_version" not in script
    assert "[string]$stored.instance_id" not in script
    assert "[string]$payload.instance_id" not in script
    assert len(script.encode("utf-8")) <= 16 * 1024
