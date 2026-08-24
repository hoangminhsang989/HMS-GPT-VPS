from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import AgentPackageFile, AgentPackageManifest
from hms_gpt_vps.agent_service_install import (
    AgentServiceConfig,
    build_agent_service_install_script,
)
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.vm_file_copy import VMFileArtifact, build_copy_vm_file_script


def package_manifest(digest_char: str = "a") -> AgentPackageManifest:
    return AgentPackageManifest(
        platform="windows-x64",
        version="0.1.0",
        entrypoint="hms-agent.exe",
        file_count=2,
        total_size=3,
        files=(
            AgentPackageFile(path="_internal/runtime.dll", size=2, sha256="f" * 64),
            AgentPackageFile(path="hms-agent.exe", size=1, sha256=digest_char * 64),
        ),
    )


def make_artifact(tmp_path: Path) -> VMFileArtifact:
    source = tmp_path / "hms-agent.exe"
    source.write_bytes(b"agent-binary-placeholder")
    import hashlib

    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    return VMFileArtifact(
        source=source,
        destination=r"C:\ProgramData\HMS-GPT-VPS\Agent\package\hms-agent.exe",
        sha256=digest,
    )


def runtime_config() -> AgentServiceRuntimeConfig:
    return AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=r"C:\HMS-Workspace",
        state_root=r"C:\ProgramData\HMS-GPT-VPS\State",
        python_executable=r"C:\Program Files\Python\python.exe",
        git_executable=r"C:\Program Files\Git\cmd\git.exe",
        health_port=8765,
    )


def install_script(digest_char: str = "a") -> str:
    return build_agent_service_install_script(
        AgentServiceConfig(),
        package_manifest=package_manifest(digest_char),
        runtime_config=runtime_config(),
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
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        build_copy_vm_file_script("HMS-GPT-VPS-01", bad)


def test_agent_service_uses_localservice_and_per_service_sid() -> None:
    script = install_script("a")
    assert "NT AUTHORITY\\LocalService" in script
    assert "LocalSystem" not in script
    assert "sc.exe sidtype" in script
    assert "unrestricted" in script
    assert "NT SERVICE\\$serviceName" in script
    assert "${servicePrincipal}:(OI)(CI)RX" in script
    assert "${servicePrincipal}:(OI)(CI)M" in script


def test_agent_service_verifies_complete_package_before_scm_mutation() -> None:
    script = install_script("b")
    verify_position = script.index("$packageProof = Test-HmsAgentPackageTree")
    create_position = script.index("sc.exe create")
    assert verify_position < create_position
    assert "function Test-HmsAgentPackageTree" in script
    assert "package tree file count differs from manifest" in script
    assert "package contains an unmanifested file" in script
    assert "package must not contain reparse points" in script
    assert "package file SHA-256 mismatch" in script
    assert "function Get-HmsSha256" in script
    assert "System.Security.Cryptography.SHA256" in script
    assert "Get-FileHash" not in script


def test_agent_service_uses_separate_protected_root_and_exact_package_root() -> None:
    config = AgentServiceConfig()
    config.validate()
    assert config.agent_root_path == r"C:\ProgramData\HMS-GPT-VPS\Agent"
    assert config.package_path == r"C:\ProgramData\HMS-GPT-VPS\Agent\package"
    assert config.binary_path == r"C:\ProgramData\HMS-GPT-VPS\Agent\package\hms-agent.exe"
    assert config.runtime_config_path == r"C:\ProgramData\HMS-GPT-VPS\Agent\agent-runtime.json"
    script = install_script("c")
    assert "(OI)(CI)RX" in script
    assert "(OI)(CI)M" in script
    assert "*S-1-5-18:(OI)(CI)F" in script
    assert "*S-1-5-32-544:(OI)(CI)F" in script
    assert "Everyone:(" not in script
    assert "Users:(" not in script


def test_agent_service_publishes_exact_runtime_config_before_service_start() -> None:
    config = runtime_config()
    script = install_script("d")

    assert r"C:\ProgramData\HMS-GPT-VPS\Agent\agent-runtime.json" in script
    assert config.sha256() in script
    assert "FromBase64String" in script
    assert "WriteAllBytes" in script
    assert "File]::Replace" in script
    assert "runtime config temp SHA-256 mismatch" in script
    assert "runtime_config_sha256" in script
    assert script.index("WriteAllBytes") < script.index("sc.exe create")
    assert script.index("runtime config SHA-256 mismatch") < script.index("Start-Service")


def test_agent_service_restarts_only_when_runtime_config_changed() -> None:
    script = install_script("e")

    assert "$configChanged" in script
    assert "$configChanged -and $null -ne $existing" in script
    assert "$null = Stop-Service -Name $serviceName -ErrorAction Stop -WarningAction SilentlyContinue" in script
    assert "$null = $existing.WaitForStatus(" in script
    assert "$null = $existing.Refresh()" in script
    assert "$null = Start-Service -Name $serviceName -ErrorAction Stop -WarningAction SilentlyContinue" in script
    assert "runtime_config_changed" in script


def test_agent_service_reconcile_accepts_only_safe_scm_command_canonicalizations() -> None:
    script = install_script("f")

    assert "$expectedQuotedCommand = '\"' + $binaryPath + '\" service'" in script
    assert "$expectedUnquotedCommand = $binaryPath + ' service'" in script
    assert "'binPath=' $expectedQuotedCommand" in script
    assert "$wmi.PathName -eq $expectedQuotedCommand" in script
    assert "$binaryPath -notmatch '\\s'" in script
    assert "$wmi.PathName -eq $expectedUnquotedCommand" in script
    assert "if (-not $commandOk)" in script
    assert "$wmi.PathName -ne $quotedBinary" not in script


def test_agent_service_rejects_runtime_config_outside_protected_agent_root() -> None:
    service = AgentServiceConfig(
        runtime_config_path=r"C:\ProgramData\HMS-GPT-VPS\State\agent-runtime.json"
    )
    with pytest.raises(ValueError, match="protected Agent root"):
        service.validate()


def test_agent_service_rejects_package_outside_protected_agent_root() -> None:
    service = AgentServiceConfig(
        package_path=r"C:\ProgramData\HMS-GPT-VPS\Package",
        binary_path=r"C:\ProgramData\HMS-GPT-VPS\Package\hms-agent.exe",
    )
    with pytest.raises(ValueError, match="direct child"):
        service.validate()


def test_agent_service_rejects_runtime_config_acl_target_mismatch() -> None:
    bad_runtime = AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=r"C:\Different-Workspace",
        state_root=r"C:\ProgramData\HMS-GPT-VPS\State",
        python_executable=r"C:\Program Files\Python\python.exe",
        git_executable=r"C:\Program Files\Git\cmd\git.exe",
        health_port=8765,
    )
    with pytest.raises(ValueError, match="workspace_root conflicts"):
        build_agent_service_install_script(
            AgentServiceConfig(),
            package_manifest=package_manifest("f"),
            runtime_config=bad_runtime,
        )
