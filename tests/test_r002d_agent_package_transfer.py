from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import (
    build_agent_package_manifest,
    write_agent_package_manifest,
)
from hms_gpt_vps.agent_package_transfer import (
    AgentPackageTransferPlan,
    build_copy_agent_package_to_staging_script,
    build_prepare_agent_package_staging_script,
    build_publish_agent_package_script,
)


TRANSFER_ID = "1" * 32
OWNERSHIP_TOKEN = "2" * 48


def make_package(tmp_path: Path) -> tuple[Path, Path, object]:
    package = tmp_path / "hms-agent"
    internal = package / "_internal"
    internal.mkdir(parents=True)
    (package / "hms-agent.exe").write_bytes(b"agent-entrypoint")
    (internal / "python313.dll").write_bytes(b"python-runtime")
    (internal / "module.pyd").write_bytes(b"extension-module")
    manifest = build_agent_package_manifest(package, version="0.1.0")
    manifest_path = tmp_path / "hms-agent.manifest.json"
    write_agent_package_manifest(manifest_path, manifest)
    return package, manifest_path, manifest


def make_plan(tmp_path: Path) -> AgentPackageTransferPlan:
    package, manifest_path, manifest = make_package(tmp_path)
    return AgentPackageTransferPlan.create(
        package,
        manifest_path,
        manifest,
        transfer_id=TRANSFER_ID,
        ownership_token=OWNERSHIP_TOKEN,
    )


def test_transfer_layout_is_unique_staged_and_manifest_stays_outside_package_tree(
    tmp_path: Path,
) -> None:
    plan = make_plan(tmp_path)

    assert plan.layout.transfer_root == (
        rf"C:\ProgramData\HMS-GPT-VPS\Staging\AgentPackage\{TRANSFER_ID}"
    )
    assert plan.layout.staging_package_root.endswith(rf"{TRANSFER_ID}\package")
    assert plan.layout.staging_manifest_path.endswith(
        rf"{TRANSFER_ID}\hms-agent.manifest.json"
    )
    assert plan.layout.final_package_root == r"C:\ProgramData\HMS-GPT-VPS\Agent\package"
    assert plan.layout.final_manifest_path == (
        r"C:\ProgramData\HMS-GPT-VPS\Agent\hms-agent.manifest.json"
    )
    assert "ownership_token" not in repr(plan)
    assert OWNERSHIP_TOKEN not in repr(plan)


def test_transfer_plan_rejects_host_package_tamper_before_script_generation(
    tmp_path: Path,
) -> None:
    plan = make_plan(tmp_path)
    (plan.source_root / "_internal" / "module.pyd").write_bytes(b"tampered")

    with pytest.raises(ValueError, match="size mismatch|SHA-256 mismatch"):
        build_copy_agent_package_to_staging_script("HMS-GPT-VPS-01", plan)


def test_transfer_plan_rejects_manifest_inside_exact_package_tree(tmp_path: Path) -> None:
    package, manifest_path, manifest = make_package(tmp_path)
    inside = package / "hms-agent.manifest.json"
    inside.write_bytes(manifest_path.read_bytes())

    with pytest.raises(ValueError, match="tree differs from manifest|outside"):
        AgentPackageTransferPlan.create(
            package,
            inside,
            manifest,
            transfer_id=TRANSFER_ID,
            ownership_token=OWNERSHIP_TOKEN,
        )


def test_prepare_script_never_deletes_and_creates_exact_ownership_marker(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    script = build_prepare_agent_package_staging_script(plan)

    assert plan.layout.transfer_root in script
    assert plan.layout.ownership_marker_path in script
    assert OWNERSHIP_TOKEN in script
    assert "transfer root already exists" in script
    assert "ReparsePoint" in script
    assert "WriteAllText" in script
    assert "Remove-Item" not in script


def test_copy_script_uses_one_bounded_guest_service_interface_window(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    script = build_copy_agent_package_to_staging_script("HMS-GPT-VPS-01", plan)

    assert script.count("Enable-VMIntegrationService") == 1
    assert script.count("Disable-VMIntegrationService") == 1
    assert "$enabledTemporarily" in script
    assert "finally" in script
    assert "Guest Service Interface" in script
    assert "-FileSource Host" in script
    assert "-CreateFullPath" in script
    assert " -Force" not in script
    assert "Get-HmsSha256 $source" in script
    assert script.index("Get-HmsSha256 $source") < script.index("Copy-VMFile -Name $vmName")
    assert "manifest source hash changed before copy" in script
    assert plan.layout.staging_package_root in script
    assert plan.layout.final_package_root not in script


def test_publish_script_verifies_staging_before_any_final_package_move(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    script = build_publish_agent_package_script(plan)

    staged_verify = script.index("$stagedProof = Test-HmsAgentPackageTree")
    final_move = script.index("Move-Item -LiteralPath $stagingPackage")
    assert staged_verify < final_move
    assert "Existing HMS Agent manifest conflicts with staged package" in script
    assert script.index("Existing HMS Agent manifest conflicts") < final_move
    assert "$alreadyPublished = Test-Path -LiteralPath $finalPackage -PathType Container" in script
    assert "$finalProof = Test-HmsAgentPackageTree $finalPackage $manifestPayload" in script
    assert "Existing HMS Agent package target is not a directory" in script
    assert "final package proof differs from staged proof" in script
    assert "Refusing to clean HMS Agent staging without exact ownership marker" in script
    assert plan.layout.final_manifest_path in script
    assert plan.layout.final_manifest_path not in plan.layout.final_package_root


def test_publish_guest_script_fits_powershell_direct_bootstrap_limit(tmp_path: Path) -> None:
    # The manifest is copied as a separate staged file and read inside the guest;
    # it is deliberately not embedded into this script, keeping the script under
    # the existing 16 KiB PowerShell Direct bootstrap cap even as package contents grow.
    script = build_publish_agent_package_script(make_plan(tmp_path))
    assert len(script.encode("utf-8")) <= 16 * 1024


def test_transfer_ids_and_ownership_tokens_are_strict_lowercase_hex(tmp_path: Path) -> None:
    package, manifest_path, manifest = make_package(tmp_path)

    with pytest.raises(ValueError, match="transfer_id"):
        AgentPackageTransferPlan.create(
            package,
            manifest_path,
            manifest,
            transfer_id="Z" * 32,
            ownership_token=OWNERSHIP_TOKEN,
        )
    with pytest.raises(ValueError, match="ownership token"):
        AgentPackageTransferPlan.create(
            package,
            manifest_path,
            manifest,
            transfer_id=TRANSFER_ID,
            ownership_token="A" * 48,
        )
