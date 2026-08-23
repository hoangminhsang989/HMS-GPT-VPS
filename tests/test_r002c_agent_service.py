from pathlib import Path

from hms_gpt_vps.agent_service_install import (
    AgentServiceConfig,
    build_agent_service_install_script,
)
from hms_gpt_vps.vm_file_copy import VMFileArtifact, build_copy_vm_file_script


def make_artifact(tmp_path: Path) -> VMFileArtifact:
    source = tmp_path / "hms-agent.exe"
    source.write_bytes(b"agent-binary-placeholder")
    import hashlib

    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    return VMFileArtifact(
        source=source,
        destination=r"C:\ProgramData\HMS-GPT-VPS\Agent\hms-agent.exe",
        sha256=digest,
    )


def test_copy_vm_file_temporarily_enables_guest_service_interface(tmp_path: Path) -> None:
    artifact = make_artifact(tmp_path)
    script = build_copy_vm_file_script("HMS-GPT-VPS-01", artifact)
    assert "Guest Service Interface" in script
    assert "Enable-VMIntegrationService" in script
    assert "Copy-VMFile" in script
    assert "-FileSource Host" in script
    assert "-CreateFullPath" in script
    assert "finally" in script
    assert "Disable-VMIntegrationService" in script
    assert "SMB" not in script


def test_copy_vm_file_validates_host_hash_before_script_build(tmp_path: Path) -> None:
    artifact = make_artifact(tmp_path)
    bad = VMFileArtifact(
        source=artifact.source,
        destination=artifact.destination,
        sha256="0" * 64,
    )
    try:
        build_copy_vm_file_script("HMS-GPT-VPS-01", bad)
    except ValueError as exc:
        assert "SHA-256 mismatch" in str(exc)
    else:
        raise AssertionError("tampered host artifact must be rejected")


def test_agent_service_uses_localservice_and_per_service_sid() -> None:
    script = build_agent_service_install_script(
        AgentServiceConfig(),
        expected_sha256="a" * 64,
    )
    assert "NT AUTHORITY\\LocalService" in script
    assert "LocalSystem" not in script
    assert "sc.exe sidtype" in script
    assert "unrestricted" in script
    assert "NT SERVICE\\$serviceName" in script
    assert "${servicePrincipal}:(OI)(CI)RX" in script
    assert "${servicePrincipal}:(OI)(CI)M" in script


def test_agent_service_hash_verifies_guest_binary_before_scm_mutation() -> None:
    script = build_agent_service_install_script(
        AgentServiceConfig(),
        expected_sha256="b" * 64,
    )
    hash_position = script.index("Get-FileHash")
    create_position = script.index("sc.exe create")
    assert hash_position < create_position
    assert "SHA-256 mismatch inside guest" in script


def test_agent_service_protects_binary_workspace_and_state_differently() -> None:
    script = build_agent_service_install_script(
        AgentServiceConfig(),
        expected_sha256="c" * 64,
    )
    assert "(OI)(CI)RX" in script
    assert "(OI)(CI)M" in script
    assert "*S-1-5-18:(OI)(CI)F" in script
    assert "*S-1-5-32-544:(OI)(CI)F" in script
    assert "Everyone:(" not in script
    assert "Users:(" not in script
