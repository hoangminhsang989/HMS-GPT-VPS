from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from hms_gpt_vps.agent_service_install import (
    AgentServiceConfig,
    build_agent_service_install_script,
)
from hms_gpt_vps.agent_service_readiness import build_agent_service_readiness_script
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.powershell import ps_literal, run_powershell_json
from hms_gpt_vps.powershell_sha256 import POWERSHELL_SHA256_FUNCTION


def _runtime_config() -> AgentServiceRuntimeConfig:
    return AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="sha-test-instance",
        project_id="sha-test-project",
        bridge_origin="https://127.0.0.1:9443",
        workspace_root=r"C:\HMS-Workspace",
        state_root=r"C:\ProgramData\HMS-GPT-VPS\State",
        python_executable=r"C:\Windows\System32\cmd.exe",
        git_executable=r"C:\Program Files\Git\cmd\git.exe",
        health_port=18765,
    )


def test_service_scripts_use_cmdlet_independent_sha256() -> None:
    config = AgentServiceConfig()
    runtime = _runtime_config()
    expected = "ab" * 32

    install = build_agent_service_install_script(
        config,
        expected_sha256=expected,
        runtime_config=runtime,
    )
    readiness = build_agent_service_readiness_script(
        config,
        expected_sha256=expected,
        runtime_config=runtime,
    )

    for script in (install, readiness):
        assert "function Get-HmsSha256" in script
        assert "Get-FileHash" not in script
        assert "System.Security.Cryptography.SHA256" in script


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_native_powershell_sha256_matches_python(tmp_path: Path) -> None:
    payload = b"HMS-GPT-VPS\x00sha256\r\nqualification"
    artifact = tmp_path / "sha256-probe.bin"
    artifact.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()

    result = run_powershell_json(
        POWERSHELL_SHA256_FUNCTION
        + "\n[pscustomobject]@{ sha256 = (Get-HmsSha256 "
        + ps_literal(str(artifact))
        + ") }"
    )

    assert result == {"sha256": expected}
