from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import (
    build_agent_package_manifest,
    write_agent_package_manifest,
)
from hms_gpt_vps.agent_package_transfer import AgentPackageTransferPlan
from hms_gpt_vps.agent_package_transfer_recovery import (
    build_agent_package_ready_probe_script,
    build_reset_owned_agent_package_staging_script,
)
from hms_gpt_vps.agent_post_install_observe import (
    AgentPostInstallObservationConfig,
    AgentPostInstallObserver,
)
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps import agent_post_install_observe as observe_module


TRANSFER_ID = "1" * 32
OWNERSHIP_TOKEN = "2" * 48


def package(tmp_path: Path):
    root = tmp_path / "hms-agent"
    root.mkdir()
    (root / "hms-agent.exe").write_bytes(b"entrypoint")
    manifest = build_agent_package_manifest(root, version="0.1.0")
    manifest_path = tmp_path / "hms-agent.manifest.json"
    write_agent_package_manifest(manifest_path, manifest)
    return root, manifest_path, manifest


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


def test_owned_staging_reset_checks_exact_marker_before_delete(tmp_path: Path) -> None:
    root, manifest_path, manifest = package(tmp_path)
    plan = AgentPackageTransferPlan.create(
        root,
        manifest_path,
        manifest,
        transfer_id=TRANSFER_ID,
        ownership_token=OWNERSHIP_TOKEN,
    )
    script = build_reset_owned_agent_package_staging_script(plan)

    assert "transfer ownership marker is missing" in script
    assert "transfer ownership marker does not match" in script
    assert "ReparsePoint" in script
    marker_check = script.index("ReadAllText($markerPath) -cne $ownershipToken")
    destructive = script.index("Remove-Item -LiteralPath $transferRoot")
    assert marker_check < destructive
    assert script.count("Remove-Item -LiteralPath $transferRoot") == 1


def test_package_ready_probe_is_read_only_and_verifies_complete_tree(tmp_path: Path) -> None:
    _, _, manifest = package(tmp_path)
    script = build_agent_package_ready_probe_script(AgentServiceConfig(), manifest)

    assert "Test-HmsAgentPackageTree" in script
    assert "hms-agent.manifest.json" in script
    assert "Get-HmsSha256 $manifestPath" in script
    assert "package_ready" in script
    assert "Remove-Item" not in script
    assert "Move-Item" not in script
    assert "Copy-VMFile" not in script


def test_post_install_observer_passes_full_manifest_to_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, manifest = package(tmp_path)
    captured: dict[str, object] = {}

    def readiness(*args: object, **kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"service_ready": False}

    monkeypatch.setattr(observe_module, "probe_agent_service_readiness", readiness)
    observer = AgentPostInstallObserver(
        AgentPostInstallObservationConfig(
            vm_name="HMS-GPT-VPS-01",
            package_manifest=manifest,
            expected_agent_version=manifest.version,
            service=AgentServiceConfig(),
            runtime=runtime_config(),
        )
    )
    result = observer.observe(PowerShellDirectCredential("hmsbootstrap", "Aa1!test"))

    assert captured["package_manifest"] == manifest
    assert "expected_sha256" not in captured
    assert result.service_ready is False
    assert result.health_error == "service_not_ready"


def test_post_install_observer_rejects_version_not_bound_to_manifest(tmp_path: Path) -> None:
    _, _, manifest = package(tmp_path)
    config = AgentPostInstallObservationConfig(
        vm_name="HMS-GPT-VPS-01",
        package_manifest=manifest,
        expected_agent_version="different-version",
        service=AgentServiceConfig(),
        runtime=runtime_config(),
    )
    with pytest.raises(ValueError, match="must match approved package manifest"):
        config.validate()
