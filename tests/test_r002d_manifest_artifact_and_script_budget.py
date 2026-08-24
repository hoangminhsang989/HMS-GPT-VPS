from __future__ import annotations

from pathlib import Path

from hms_gpt_vps.agent_package import AgentPackageFile, AgentPackageManifest, write_agent_package_manifest
from hms_gpt_vps.agent_package_manifest_artifact import (
    canonical_agent_package_manifest_bytes,
    canonical_agent_package_manifest_sha256,
    canonical_agent_package_manifest_size,
)
from hms_gpt_vps.agent_service_install import AgentServiceConfig, build_agent_service_install_script
from hms_gpt_vps.agent_service_readiness import build_agent_service_readiness_script
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)


MAX_GUEST_SCRIPT_BYTES = 16 * 1024


def large_manifest(file_count: int = 4096) -> AgentPackageManifest:
    files = []
    total = 0
    for index in range(file_count - 1):
        size = index + 1
        total += size
        files.append(
            AgentPackageFile(
                path=f"_internal/m{index:04d}.bin",
                size=size,
                sha256=f"{index % 16:x}" * 64,
            )
        )
    entry_size = 1
    total += entry_size
    files.append(AgentPackageFile(path="hms-agent.exe", size=entry_size, sha256="f" * 64))
    files.sort(key=lambda item: (item.path.casefold(), item.path))
    manifest = AgentPackageManifest(
        platform="windows-x64",
        version="0.1.0",
        entrypoint="hms-agent.exe",
        file_count=len(files),
        total_size=total,
        files=tuple(files),
    )
    manifest.validate()
    return manifest


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


def test_canonical_manifest_bytes_are_exact_writer_contract(tmp_path: Path) -> None:
    manifest = large_manifest(4)
    target = tmp_path / "hms-agent.manifest.json"
    write_agent_package_manifest(target, manifest)

    data = canonical_agent_package_manifest_bytes(manifest)
    assert target.read_bytes() == data
    assert canonical_agent_package_manifest_size(manifest) == len(data)
    import hashlib

    assert canonical_agent_package_manifest_sha256(manifest) == hashlib.sha256(data).hexdigest()


def test_install_and_readiness_scripts_do_not_scale_with_full_manifest_payload() -> None:
    manifest = large_manifest()
    runtime = runtime_config()
    service = AgentServiceConfig()

    install = build_agent_service_install_script(
        service,
        package_manifest=manifest,
        runtime_config=runtime,
    )
    readiness = build_agent_service_readiness_script(
        service,
        package_manifest=manifest,
        runtime_config=runtime,
    )

    assert manifest.to_json() not in install
    assert manifest.to_json() not in readiness
    assert r"C:\ProgramData\HMS-GPT-VPS\Agent\hms-agent.manifest.json" in install
    assert r"C:\ProgramData\HMS-GPT-VPS\Agent\hms-agent.manifest.json" in readiness
    assert len(install.encode("utf-8")) <= MAX_GUEST_SCRIPT_BYTES
    assert len(readiness.encode("utf-8")) <= MAX_GUEST_SCRIPT_BYTES
