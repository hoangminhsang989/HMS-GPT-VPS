from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import (
    build_agent_package_manifest,
    write_agent_package_manifest,
)
from hms_gpt_vps.agent_package_transfer_attempt import AgentPackageTransferAttemptStore
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.instance_registry import InstanceRegistry, VMRecord
from hms_gpt_vps.managed_agent_provisioning_runtime import (
    ManagedAgentProvisioningConfig,
    ManagedAgentProvisioningError,
    ManagedAgentProvisioningRuntime,
)


VM_ID = "11111111-2222-3333-4444-555555555555"
VM_NAME = "HMS-GPT-VPS-01"


class MemorySecretStore:
    def __init__(self) -> None:
        self.value: str | None = None

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("secret missing")
        return self.value

    def clear(self) -> None:
        self.value = None


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


def make_package(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "package-source"
    root.mkdir()
    (root / "hms-agent.exe").write_bytes(b"entrypoint")
    manifest = build_agent_package_manifest(root, version="0.1.0")
    manifest_path = tmp_path / "hms-agent.manifest.json"
    write_agent_package_manifest(manifest_path, manifest)
    return root, manifest_path


def write_registry(path: Path) -> None:
    InstanceRegistry(path).upsert(
        VMRecord(
            instance_id="hms-01",
            vm_name=VM_NAME,
            backend="hyperv",
            phase="vm_created",
            workspace_path=r"C:\HMS-Workspace",
            vm_id=VM_ID,
        )
    )


def config(package: Path, manifest: Path, registry: Path) -> ManagedAgentProvisioningConfig:
    return ManagedAgentProvisioningConfig(
        instance_id="hms-01",
        vm_name=VM_NAME,
        package_source_root=package,
        package_manifest_path=manifest,
        registry_path=registry,
        service=AgentServiceConfig(),
        runtime=runtime_config(),
    )


def test_config_rejects_registry_beneath_symlinked_parent(tmp_path: Path) -> None:
    package, manifest = make_package(tmp_path)
    real_parent = tmp_path / "registry-real"
    real_parent.mkdir()
    write_registry(real_parent / "instances.json")
    linked_parent = tmp_path / "registry-link"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(ValueError, match="must not traverse a link or reparse point"):
        config(package, manifest, linked_parent / "instances.json").validate()


def test_runtime_rechecks_registry_path_after_parent_is_redirected(tmp_path: Path) -> None:
    package, manifest = make_package(tmp_path)
    authority = tmp_path / "registry-authority"
    authority.mkdir()
    registry = authority / "instances.json"
    write_registry(registry)

    attempt_store = AgentPackageTransferAttemptStore(
        tmp_path / "transfer.json",
        MemorySecretStore(),
    )
    runtime = ManagedAgentProvisioningRuntime(
        config(package, manifest, registry),
        attempt_store,
    )

    relocated = tmp_path / "registry-relocated"
    authority.rename(relocated)
    try:
        authority.symlink_to(relocated, target_is_directory=True)
    except OSError:
        relocated.rename(authority)
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(ManagedAgentProvisioningError, match="authority path traverses"):
        runtime._expected_vm_id()
