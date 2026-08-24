from __future__ import annotations

import pytest

from hms_gpt_vps.agent_package import AgentPackageFile, AgentPackageManifest
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.agent_service_readiness import (
    build_agent_service_readiness_script,
    require_agent_service_ready,
)
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)


def package_manifest() -> AgentPackageManifest:
    return AgentPackageManifest(
        platform="windows-x64",
        version="0.1.0",
        entrypoint="hms-agent.exe",
        file_count=2,
        total_size=3,
        files=(
            AgentPackageFile(path="_internal/runtime.dll", size=2, sha256="b" * 64),
            AgentPackageFile(path="hms-agent.exe", size=1, sha256="a" * 64),
        ),
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


def test_service_readiness_requires_exact_package_runtime_config_hash_and_acl() -> None:
    runtime = runtime_config()
    manifest = package_manifest()
    script = build_agent_service_readiness_script(
        AgentServiceConfig(),
        package_manifest=manifest,
        runtime_config=runtime,
    )

    assert runtime.sha256() in script
    assert "Test-HmsAgentPackageTree" in script
    assert "packageTreeOk" in script
    assert "package_file_count" in script
    assert "package_total_size" in script
    assert "agentRootLayoutOk" in script
    assert "runtimeConfigExists" in script
    assert "runtimeConfigHashOk" in script
    assert "runtimeConfigRead" in script
    assert "runtime_config_sha256_ok" in script
    assert "$actualRuntimeConfigHash = Get-HmsSha256 $runtimeConfigPath" in script
    assert "Get-FileHash" not in script
    service_ready_block = script[script.index("$serviceReady ="):script.index("[pscustomobject]")]
    assert "$packageTreeOk" in service_ready_block
    assert "$agentRootLayoutOk" in service_ready_block
    assert "$runtimeConfigExists" in service_ready_block
    assert "$runtimeConfigHashOk" in service_ready_block
    assert "$runtimeConfigRead" in service_ready_block


def test_service_readiness_rejects_runtime_acl_target_mismatch() -> None:
    bad = AgentServiceRuntimeConfig(
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
        build_agent_service_readiness_script(
            AgentServiceConfig(),
            package_manifest=package_manifest(),
            runtime_config=bad,
        )


def test_require_agent_service_ready_remains_fail_closed() -> None:
    require_agent_service_ready({"service_ready": True})
    with pytest.raises(RuntimeError, match="readiness contract failed"):
        require_agent_service_ready({"service_ready": False})
