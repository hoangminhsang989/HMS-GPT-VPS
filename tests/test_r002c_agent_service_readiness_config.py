from __future__ import annotations

import pytest

from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.agent_service_readiness import (
    build_agent_service_readiness_script,
    require_agent_service_ready,
)
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
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


def test_service_readiness_requires_exact_runtime_config_hash_and_acl() -> None:
    runtime = runtime_config()
    script = build_agent_service_readiness_script(
        AgentServiceConfig(),
        expected_sha256="a" * 64,
        runtime_config=runtime,
    )

    assert runtime.sha256() in script
    assert "runtimeConfigExists" in script
    assert "runtimeConfigHashOk" in script
    assert "runtimeConfigInAgentRoot" in script
    assert "runtimeConfigRead" in script
    assert "runtime_config_sha256_ok" in script
    assert "Get-FileHash -LiteralPath $runtimeConfigPath" in script
    service_ready_block = script[script.index("$serviceReady ="):script.index("[pscustomobject]")]
    assert "$runtimeConfigExists" in service_ready_block
    assert "$runtimeConfigHashOk" in service_ready_block
    assert "$runtimeConfigInAgentRoot" in service_ready_block
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
            expected_sha256="b" * 64,
            runtime_config=bad,
        )


def test_require_agent_service_ready_remains_fail_closed() -> None:
    require_agent_service_ready({"service_ready": True})
    with pytest.raises(RuntimeError, match="readiness contract failed"):
        require_agent_service_ready({"service_ready": False})
