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
from hms_gpt_vps.managed_agent_provisioning_runtime import (
    ManagedAgentProvisioningConfig,
    ManagedAgentProvisioningError,
    ManagedAgentProvisioningRuntime,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps import managed_agent_provisioning_runtime as runtime_module


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

    secret_store = MemorySecretStore()
    attempt_store = AgentPackageTransferAttemptStore(
        tmp_path / "transfer-attempt.json",
        secret_store,
    )
    runtime = ManagedAgentProvisioningRuntime(
        ManagedAgentProvisioningConfig(
            instance_id="hms-01",
            vm_name="HMS-GPT-VPS-01",
            package_source_root=package,
            package_manifest_path=manifest_path,
            service=AgentServiceConfig(),
            runtime=runtime_config(),
        ),
        attempt_store,
    )
    return runtime, attempt_store, manifest


def credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "Aa1!test-secret")


def test_stage_retry_reuses_exact_owned_attempt_after_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, store, manifest = build_runtime(tmp_path)
    seen: list[tuple[str, str]] = []
    monkeypatch.setattr(
        runtime_module,
        "reset_owned_agent_package_staging",
        lambda *args, **kwargs: {"reset": True},
    )

    def interrupted(*args: object, **kwargs: object) -> dict[str, object]:
        plan = args[2]
        seen.append((plan.layout.transfer_id, plan.ownership_token))
        raise TimeoutError("simulated host interruption")

    monkeypatch.setattr(runtime_module, "transfer_agent_package_to_guest", interrupted)
    with pytest.raises(TimeoutError):
        runtime.stage_package(credential())

    current = store.load()
    assert current is not None
    assert current.phase is AgentPackageTransferPhase.TRANSFERRING

    def completed(*args: object, **kwargs: object) -> dict[str, object]:
        plan = args[2]
        seen.append((plan.layout.transfer_id, plan.ownership_token))
        return {
            "published": True,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        }

    monkeypatch.setattr(runtime_module, "transfer_agent_package_to_guest", completed)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready",
        lambda *args, **kwargs: {
            "package_ready": True,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        },
    )
    result = runtime.stage_package(credential())

    assert result["package_ready"] is True
    assert len(seen) == 2
    assert seen[0] == seen[1]
    assert store.load() is None


def test_published_attempt_only_reprobes_and_never_retransfers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, store, manifest = build_runtime(tmp_path)
    manifest_sha = canonical_agent_package_manifest_sha256(manifest)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256=manifest_sha,
    )
    store.transition(AgentPackageTransferPhase.PLANNED, AgentPackageTransferPhase.TRANSFERRING)
    store.transition(AgentPackageTransferPhase.TRANSFERRING, AgentPackageTransferPhase.PUBLISHED)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("published retry must not mutate or retransfer")

    monkeypatch.setattr(runtime_module, "reset_owned_agent_package_staging", forbidden)
    monkeypatch.setattr(runtime_module, "transfer_agent_package_to_guest", forbidden)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready",
        lambda *args, **kwargs: {
            "package_ready": True,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        },
    )

    result = runtime.stage_package(credential())
    assert result["resumed_published_attempt"] is True
    assert store.load() is None


def test_published_attempt_with_lost_final_proof_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, store, manifest = build_runtime(tmp_path)
    store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256=canonical_agent_package_manifest_sha256(manifest),
    )
    store.transition(AgentPackageTransferPhase.PLANNED, AgentPackageTransferPhase.TRANSFERRING)
    store.transition(AgentPackageTransferPhase.TRANSFERRING, AgentPackageTransferPhase.PUBLISHED)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready",
        lambda *args, **kwargs: {"package_ready": False},
    )

    with pytest.raises(ManagedAgentProvisioningError, match="no longer has an exact final proof"):
        runtime.stage_package(credential())
    assert store.load() is not None


def test_service_install_requires_package_ready_before_scm_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _, _ = build_runtime(tmp_path)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready",
        lambda *args, **kwargs: {"package_ready": False},
    )

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("SCM installer must not run")

    monkeypatch.setattr(runtime_module, "install_agent_service", forbidden)
    with pytest.raises(ManagedAgentProvisioningError, match="requires exact package-ready proof"):
        runtime.install_service(credential())


def test_service_install_runs_only_after_exact_package_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _, manifest = build_runtime(tmp_path)
    monkeypatch.setattr(
        runtime_module,
        "probe_agent_package_ready",
        lambda *args, **kwargs: {
            "package_ready": True,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        },
    )
    calls = {"count": 0}

    def installed(*args: object, **kwargs: object) -> dict[str, object]:
        calls["count"] += 1
        return {"ready": True}

    monkeypatch.setattr(runtime_module, "install_agent_service", installed)
    assert runtime.install_service(credential())["ready"] is True
    assert calls["count"] == 1
