from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import (
    build_agent_package_manifest,
    write_agent_package_manifest,
)
from hms_gpt_vps.agent_package_manifest_artifact import (
    canonical_agent_package_manifest_sha256,
)
from hms_gpt_vps.agent_package_transfer_attempt import (
    AgentPackageTransferAttemptStore,
    AgentPackageTransferPhase,
)
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
OTHER_VM_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
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


def build_runtime(tmp_path: Path) -> tuple[ManagedAgentProvisioningRuntime, AgentPackageTransferAttemptStore, object]:
    package = tmp_path / "hms-agent"
    internal = package / "_internal"
    internal.mkdir(parents=True)
    (package / "hms-agent.exe").write_bytes(b"entrypoint")
    (internal / "runtime.dll").write_bytes(b"runtime")
    manifest = build_agent_package_manifest(package, version="0.1.0")
    manifest_path = tmp_path / "hms-agent.manifest.json"
    write_agent_package_manifest(manifest_path, manifest)

    registry_path = tmp_path / "instances.json"
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

    secret_store = MemorySecretStore()
    attempt_store = AgentPackageTransferAttemptStore(
        tmp_path / "transfer-attempt.json",
        secret_store,
    )
    runtime = ManagedAgentProvisioningRuntime(
        ManagedAgentProvisioningConfig(
            instance_id="hms-01",
            vm_name=VM_NAME,
            package_source_root=package,
            package_manifest_path=manifest_path,
            registry_path=registry_path,
            service=AgentServiceConfig(),
            runtime=runtime_config(),
        ),
        attempt_store,
    )
    return runtime, attempt_store, manifest


def credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "Aa1!test-secret")


def install_vm_identity_mock(
    monkeypatch: pytest.MonkeyPatch,
    *,
    observed_vm_id: str = VM_ID,
    observed_vm_name: str = VM_NAME,
) -> list[str]:
    scripts: list[str] = []

    def identity_probe(script: str, *, timeout_seconds: int, **_kwargs: object):
        scripts.append(script)
        assert timeout_seconds == 30
        return {"vm_id": observed_vm_id, "vm_name": observed_vm_name}

    monkeypatch.setattr(runtime_module, "run_powershell_json", identity_probe)
    return scripts


def install_host_integration_mocks(
    monkeypatch: pytest.MonkeyPatch,
    *,
    baseline: bool = False,
) -> list[bool]:
    restored: list[bool] = []

    def probe(vm_id: str, vm_name: str) -> bool:
        assert vm_id == VM_ID
        assert vm_name == VM_NAME
        return baseline

    monkeypatch.setattr(
        runtime_module,
        "probe_guest_service_interface_enabled_by_id",
        probe,
    )

    def restore(vm_id: str, vm_name: str, expected_enabled: bool):  # type: ignore[no-untyped-def]
        assert vm_id == VM_ID
        assert vm_name == VM_NAME
        restored.append(expected_enabled)
        return {
            "restored": True,
            "enabled": expected_enabled,
            "changed": False,
            "vm_id": VM_ID,
        }

    monkeypatch.setattr(
        runtime_module,
        "restore_guest_service_interface_state_by_id",
        restore,
    )
    return restored


def test_vm_name_reuse_with_different_vm_id_fails_before_guest_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _, _ = build_runtime(tmp_path)
    scripts = install_vm_identity_mock(monkeypatch, observed_vm_id=OTHER_VM_ID)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("guest mutation/probe must not run after VMId mismatch")

    monkeypatch.setattr(runtime_module, "probe_agent_package_ready_by_id", forbidden)
    monkeypatch.setattr(runtime_module, "install_agent_service_by_id", forbidden)

    with pytest.raises(ManagedAgentProvisioningError, match="does not match persisted"):
        runtime.install_service(credential())
    assert scripts
    assert "Get-VM -Id $expectedVmId" in scripts[0]
    assert VM_ID in scripts[0]


def test_registry_backend_must_be_hyperv_before_late_guest_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _, _ = build_runtime(tmp_path)
    runtime.registry.upsert(
        VMRecord(
            instance_id="hms-01",
            vm_name=VM_NAME,
            backend="other",
            phase="vm_created",
            workspace_path=r"C:\HMS-Workspace",
            vm_id=VM_ID,
        )
    )

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("host VM probe must not run for non-Hyper-V registry record")

    monkeypatch.setattr(runtime_module, "run_powershell_json", forbidden)
    with pytest.raises(ManagedAgentProvisioningError, match="backend is not Hyper-V"):
        runtime.install_service(credential())


def test_stage_retry_reuses_exact_owned_attempt_and_restores_host_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, store, manifest = build_runtime(tmp_path)
    install_vm_identity_mock(monkeypatch)
    seen: list[tuple[str, str]] = []
    restored = install_host_integration_mocks(monkeypatch, baseline=False)

    def reset(vm_id: str, vm_name: str, *_args: object, **_kwargs: object):
        assert vm_id == VM_ID
        assert vm_name == VM_NAME
        return {"reset": True}

    monkeypatch.setattr(runtime_module, "reset_owned_agent_package_staging_by_id", reset)

    def interrupted(*args: object, **kwargs: object) -> dict[str, object]:
        assert args[0] == VM_ID
        assert args[1] == VM_NAME
        plan = args[3]
        seen.append((plan.layout.transfer_id, plan.ownership_token))
        raise TimeoutError("simulated host interruption")

    monkeypatch.setattr(runtime_module, "transfer_agent_package_to_guest_by_id", interrupted)
    with pytest.raises(TimeoutError):
        runtime.stage_package(credential())

    current = store.load()
    assert current is not None
    assert current.phase is AgentPackageTransferPhase.TRANSFERRING
    assert current.guest_service_interface_was_enabled is False
    assert restored == [False, False]

    def completed(*args: object, **kwargs: object) -> dict[str, object]:
        assert args[0] == VM_ID
        assert args[1] == VM_NAME
        plan = args[3]
        seen.append((plan.layout.transfer_id, plan.ownership_token))
        return {
            "published": True,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
            "vm_id": VM_ID,
        }

    monkeypatch.setattr(runtime_module, "transfer_agent_package_to_guest_by_id", completed)

    def package_ready(vm_id: str, vm_name: str, *_args: object, **_kwargs: object):
        assert vm_id == VM_ID
        assert vm_name == VM_NAME
        return {
            "package_ready": True,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        }

    monkeypatch.setattr(runtime_module, "probe_agent_package_ready_by_id", package_ready)
    result = runtime.stage_package(credential())

    assert result["package_ready"] is True
    assert result["guest_service_interface_restored"] is True
    assert len(seen) == 2
    assert seen[0] == seen[1]
    assert restored == [False, False, False, False]
    assert store.load() is None


def test_enabled_integration_baseline_is_preserved_not_forced_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _, manifest = build_runtime(tmp_path)
    install_vm_identity_mock(monkeypatch)
    restored = install_host_integration_mocks(monkeypatch, baseline=True)
    monkeypatch.setattr(
        runtime_module,
        "reset_owned_agent_package_staging_by_id",
        lambda vm_id, vm_name, *args, **kwargs: {"reset": vm_id == VM_ID and vm_name == VM_NAME},
    )
    monkeypatch.setattr(
        runtime_module,
        "transfer_agent_package_to_guest_by_id",
        lambda vm_id, vm_name, *args, **kwargs: {
            "published": vm_id == VM_ID and vm_name == VM_NAME,
            "vm_id": vm_id,
        },
    )
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready_by_id",
        lambda vm_id, vm_name, *args, **kwargs: {
            "package_ready": vm_id == VM_ID and vm_name == VM_NAME,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        },
    )

    runtime.stage_package(credential())
    assert restored == [True, True]


def test_published_attempt_only_restores_host_baseline_and_reprobes_final_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, store, manifest = build_runtime(tmp_path)
    install_vm_identity_mock(monkeypatch)
    manifest_sha = canonical_agent_package_manifest_sha256(manifest)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name=VM_NAME,
        manifest_sha256=manifest_sha,
    )
    store.bind_guest_service_interface_baseline(False)
    store.transition(AgentPackageTransferPhase.PLANNED, AgentPackageTransferPhase.TRANSFERRING)
    store.transition(AgentPackageTransferPhase.TRANSFERRING, AgentPackageTransferPhase.PUBLISHED)
    restored = install_host_integration_mocks(monkeypatch, baseline=True)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("published retry must not reset guest staging or retransfer")

    monkeypatch.setattr(runtime_module, "reset_owned_agent_package_staging_by_id", forbidden)
    monkeypatch.setattr(runtime_module, "transfer_agent_package_to_guest_by_id", forbidden)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready_by_id",
        lambda vm_id, vm_name, *args, **kwargs: {
            "package_ready": vm_id == VM_ID and vm_name == VM_NAME,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        },
    )

    result = runtime.stage_package(credential())
    assert result["resumed_published_attempt"] is True
    assert restored == [False]
    assert store.load() is None


def test_published_attempt_with_lost_final_proof_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, store, manifest = build_runtime(tmp_path)
    install_vm_identity_mock(monkeypatch)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name=VM_NAME,
        manifest_sha256=canonical_agent_package_manifest_sha256(manifest),
    )
    store.bind_guest_service_interface_baseline(False)
    store.transition(AgentPackageTransferPhase.PLANNED, AgentPackageTransferPhase.TRANSFERRING)
    store.transition(AgentPackageTransferPhase.TRANSFERRING, AgentPackageTransferPhase.PUBLISHED)
    install_host_integration_mocks(monkeypatch)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready_by_id",
        lambda vm_id, vm_name, *args, **kwargs: {
            "package_ready": False if vm_id == VM_ID and vm_name == VM_NAME else True
        },
    )

    with pytest.raises(ManagedAgentProvisioningError, match="no longer has an exact final proof"):
        runtime.stage_package(credential())
    assert store.load() is not None


def test_service_install_requires_package_ready_before_scm_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _, _ = build_runtime(tmp_path)
    install_vm_identity_mock(monkeypatch)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready_by_id",
        lambda vm_id, vm_name, *args, **kwargs: {
            "package_ready": False if vm_id == VM_ID and vm_name == VM_NAME else True
        },
    )

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("SCM installer must not run")

    monkeypatch.setattr(runtime_module, "install_agent_service_by_id", forbidden)
    with pytest.raises(ManagedAgentProvisioningError, match="requires exact package-ready proof"):
        runtime.install_service(credential())


def test_service_install_runs_only_after_exact_package_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _, manifest = build_runtime(tmp_path)
    install_vm_identity_mock(monkeypatch)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready_by_id",
        lambda vm_id, vm_name, *args, **kwargs: {
            "package_ready": vm_id == VM_ID and vm_name == VM_NAME,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        },
    )
    calls = {"count": 0}

    def installed(vm_id: str, vm_name: str, *args: object, **kwargs: object) -> dict[str, object]:
        assert vm_id == VM_ID
        assert vm_name == VM_NAME
        calls["count"] += 1
        return {"ready": True}

    monkeypatch.setattr(runtime_module, "install_agent_service_by_id", installed)
    assert runtime.install_service(credential())["ready"] is True
    assert calls["count"] == 1
