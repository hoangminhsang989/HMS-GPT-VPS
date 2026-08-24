from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import (
    AgentPackageManifest,
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
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps import managed_agent_provisioning_runtime as runtime_module


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


def _build_runtime(
    tmp_path: Path,
) -> tuple[ManagedAgentProvisioningRuntime, AgentPackageManifest, Path]:
    package_authority = tmp_path / "package-authority"
    package = package_authority / "hms-agent"
    package.mkdir(parents=True)
    (package / "hms-agent.exe").write_bytes(b"entrypoint")
    manifest = build_agent_package_manifest(package, version="0.1.0")
    manifest_path = package_authority / "hms-agent.manifest.json"
    write_agent_package_manifest(manifest_path, manifest)

    registry_dir = tmp_path / "registry-authority"
    registry_dir.mkdir()
    registry_path = registry_dir / "instances.json"
    InstanceRegistry(registry_path).upsert(
        VMRecord(
            instance_id="hms-01",
            vm_name=VM_NAME,
            backend="hyperv",
            phase="vm_created",
            workspace_path=r"C:\HMS-Workspace",
            vm_id=VM_ID,
            switch_name="HMS-GPT-VPS-NAT",
            guest_ipv4="192.168.127.2",
        )
    )

    runtime = ManagedAgentProvisioningRuntime(
        ManagedAgentProvisioningConfig(
            instance_id="hms-01",
            vm_name=VM_NAME,
            package_source_root=package,
            package_manifest_path=manifest_path,
            registry_path=registry_path,
            service=AgentServiceConfig(),
            runtime=_runtime_config(),
        ),
        AgentPackageTransferAttemptStore(
            tmp_path / "transfer-attempt.json",
            MemorySecretStore(),
        ),
    )
    return runtime, manifest, package_authority


def _credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "Aa1!test-secret")


def test_managed_observation_rejects_truthy_non_boolean_package_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, manifest, _ = _build_runtime(tmp_path)
    monkeypatch.setattr(runtime, "_assert_vm_identity", lambda: VM_ID)
    monkeypatch.setattr(runtime, "_load_approved_manifest", lambda: manifest)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready_by_id",
        lambda *args, **kwargs: {"package_ready": "false"},
    )

    observation, post = runtime.observe(_credential())

    assert observation.agent_package_ready is False
    assert observation.agent_service_ready is False
    assert observation.agent_healthy is False
    assert post is None


def test_managed_install_rejects_truthy_non_boolean_service_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, manifest, _ = _build_runtime(tmp_path)
    monkeypatch.setattr(runtime, "_assert_vm_identity", lambda: VM_ID)
    monkeypatch.setattr(runtime, "_load_approved_manifest", lambda: manifest)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready_by_id",
        lambda *args, **kwargs: {"package_ready": True},
    )
    monkeypatch.setattr(
        runtime_module,
        "install_agent_service_by_id",
        lambda *args, **kwargs: {"ready": "true"},
    )

    with pytest.raises(
        ManagedAgentProvisioningError,
        match="service install did not become ready",
    ):
        runtime.install_service(_credential())


def test_managed_package_authority_redirect_after_runtime_construction_fails_closed(
    tmp_path: Path,
) -> None:
    runtime, _, package_authority = _build_runtime(tmp_path)
    preserved = tmp_path / "package-authority-preserved"
    redirected = tmp_path / "package-authority-redirected"
    redirected.mkdir()

    package_authority.rename(preserved)
    try:
        package_authority.symlink_to(redirected, target_is_directory=True)
    except OSError:
        preserved.rename(package_authority)
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(
        ManagedAgentProvisioningError,
        match="package source authority path traverses",
    ):
        runtime._load_approved_manifest()
