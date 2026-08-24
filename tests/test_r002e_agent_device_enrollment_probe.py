from __future__ import annotations

import base64
import hashlib

import pytest

from hms_gpt_vps.agent_device_credential_store import GUEST_PROTECTION_SCOPE
from hms_gpt_vps.agent_device_enrollment import AgentDeviceEnrollmentConfig
from hms_gpt_vps.agent_device_enrollment_probe import (
    AgentDeviceEnrollmentProbeError,
    build_agent_device_enrollment_probe_script,
    probe_agent_device_enrollment,
)
from hms_gpt_vps.agent_transport_protocol import AgentDeviceCredential
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps import agent_device_enrollment_probe as probe_module


SECRET = b"q" * 32
EXPECTED_PATH = r"C:\ProgramData\HMS-GPT-VPS\State\agent-device-credential.dpapi"


def device_credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id="hms-01",
        device_id="device-01",
        secret=SECRET,
    )


def enrollment_config() -> AgentDeviceEnrollmentConfig:
    return AgentDeviceEnrollmentConfig(instance_id="hms-01")


def bootstrap() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "temporary-bootstrap-secret")


def valid_probe_result() -> dict[str, object]:
    return {
        "enrollment_ready": True,
        "credential_exists": True,
        "instance_id": "hms-01",
        "device_id": "device-01",
        "protection_scope": GUEST_PROTECTION_SCOPE,
        "credential_path": EXPECTED_PATH,
    }


def test_probe_script_embeds_only_secret_digest_not_raw_secret() -> None:
    script = build_agent_device_enrollment_probe_script(
        enrollment_config(),
        device_credential(),
    )

    secret_b64 = base64.b64encode(SECRET).decode("ascii")
    secret_hex = SECRET.hex()
    secret_sha = hashlib.sha256(SECRET).hexdigest()
    assert secret_b64 not in script
    assert secret_hex not in script
    assert secret_sha in script
    assert "ProtectedData]::Unprotect" in script
    assert "DataProtectionScope]::LocalMachine" in script
    assert "ReparsePoint" in script
    assert "enrollment_ready" in script
    assert "actualSecretSha256 = $null" in script
    assert "$schemaValue -is [bool]" in script
    assert "schema_version must be an integer" in script
    assert "scalar field types are invalid" in script


def test_probe_result_is_non_secret_and_exact_identity_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(vm_name, credential, script, *, timeout_seconds):  # type: ignore[no-untyped-def]
        captured["vm_name"] = vm_name
        captured["credential"] = credential
        captured["script"] = script
        captured["timeout_seconds"] = timeout_seconds
        return valid_probe_result()

    monkeypatch.setattr(probe_module, "run_vm_powershell_json", fake_run)
    result = probe_agent_device_enrollment(
        "HMS-GPT-VPS-01",
        bootstrap(),
        enrollment_config(),
        device_credential(),
    )

    assert result["enrollment_ready"] is True
    assert result["device_id"] == "device-01"
    assert "secret" not in result
    assert "secret_sha256" not in result
    assert captured["vm_name"] == "HMS-GPT-VPS-01"
    assert captured["timeout_seconds"] == 90


@pytest.mark.parametrize(
    ("key", "value", "match"),
    [
        ("enrollment_ready", "false", "not ready"),
        ("credential_exists", "true", "existence was not proven"),
        ("instance_id", 123, "wrong instance_id"),
        ("device_id", 123, "wrong device_id"),
        ("protection_scope", 1, "not LocalMachine"),
        ("credential_path", r"C:\Other\credential.dpapi", "unexpected credential path"),
    ],
)
def test_probe_result_rejects_coerced_or_wrong_evidence(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: object,
    match: str,
) -> None:
    result = valid_probe_result()
    result[key] = value
    monkeypatch.setattr(
        probe_module,
        "run_vm_powershell_json",
        lambda *_args, **_kwargs: result,
    )

    with pytest.raises(AgentDeviceEnrollmentProbeError, match=match):
        probe_agent_device_enrollment(
            "HMS-GPT-VPS-01",
            bootstrap(),
            enrollment_config(),
            device_credential(),
        )


def test_probe_result_rejects_unknown_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    result = valid_probe_result()
    result["unexpected"] = "must-not-cross-boundary"
    monkeypatch.setattr(
        probe_module,
        "run_vm_powershell_json",
        lambda *_args, **_kwargs: result,
    )

    with pytest.raises(AgentDeviceEnrollmentProbeError, match="fields do not match schema"):
        probe_agent_device_enrollment(
            "HMS-GPT-VPS-01",
            bootstrap(),
            enrollment_config(),
            device_credential(),
        )


def test_probe_builder_rejects_bridge_credential_for_another_instance() -> None:
    wrong = AgentDeviceCredential(
        instance_id="other-instance",
        device_id="device-01",
        secret=SECRET,
    )
    with pytest.raises(ValueError, match="another instance"):
        build_agent_device_enrollment_probe_script(enrollment_config(), wrong)
