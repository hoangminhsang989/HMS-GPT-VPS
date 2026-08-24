from hms_gpt_vps.agent_package import AgentPackageFile, AgentPackageManifest
from hms_gpt_vps.agent_service_install import (
    AgentServiceConfig,
    build_agent_service_install_script,
)
from hms_gpt_vps.agent_service_readiness import build_agent_service_readiness_script
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.powershell_direct import (
    _MAX_GUEST_SCRIPT_BYTES,
    PowerShellDirectCredential,
    _direct_environment,
)


def _package_manifest() -> AgentPackageManifest:
    return AgentPackageManifest(
        platform="windows-x64",
        version="0.1.0",
        entrypoint="hms-agent.exe",
        file_count=2,
        total_size=3,
        files=(
            AgentPackageFile(path="_internal/runtime.dll", size=2, sha256="f" * 64),
            AgentPackageFile(path="hms-agent.exe", size=1, sha256="a" * 64),
        ),
    )


def _runtime_config() -> AgentServiceRuntimeConfig:
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


def test_largest_managed_guest_scripts_fit_powershell_direct_budget() -> None:
    service = AgentServiceConfig()
    manifest = _package_manifest()
    runtime = _runtime_config()
    credential = PowerShellDirectCredential(username="bootstrap", password="test-only")

    scripts = {
        "service_install": build_agent_service_install_script(
            service,
            package_manifest=manifest,
            runtime_config=runtime,
        ),
        "service_readiness": build_agent_service_readiness_script(
            service,
            package_manifest=manifest,
            runtime_config=runtime,
        ),
    }

    for name, script in scripts.items():
        encoded_size = len(script.encode("utf-8"))
        assert encoded_size <= _MAX_GUEST_SCRIPT_BYTES, (
            f"{name} is {encoded_size} bytes and exceeds the "
            f"{_MAX_GUEST_SCRIPT_BYTES}-byte PowerShell Direct guest-script budget"
        )
        environment = _direct_environment(credential, script)
        assert environment["HMS_PSDIRECT_SCRIPT_B64"]
