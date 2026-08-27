from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pytest

from hms_gpt_vps.r002f_external_deployment_bundle import (
    REVIEWED_LAUNCHER_SHA256,
    REVIEWED_STAGE0_SHA256,
    PinnedArtifact,
    PreflightAuthority,
    R002FExternalDeploymentAuthorityBundle,
    R002FExternalDeploymentBundleError,
    SealedTreeAuthority,
    render_os_trusted_launcher_command,
)


def bundle() -> R002FExternalDeploymentAuthorityBundle:
    authority = r"C:\ProgramData\HMS-GPT-VPS\Qualification\R002F"
    return R002FExternalDeploymentAuthorityBundle(
        reviewed_commit="1" * 40,
        authority_parent=authority,
        launcher=PinnedArtifact(
            authority + r"\run_r002f_external_sealed_preparation_launcher.ps1",
            REVIEWED_LAUNCHER_SHA256,
        ),
        stage0=PinnedArtifact(
            authority + r"\run_r002f_external_sealed_preparation_stage0.ps1",
            REVIEWED_STAGE0_SHA256,
        ),
        project=SealedTreeAuthority(
            source_root=r"E:\HMS_AI_Project_Bridge_SOURCE",
            manifest_path=authority + r"\project-manifest.json",
            manifest_sha256="2" * 64,
            destination_root=authority + r"\execution",
        ),
        python_runtime=SealedTreeAuthority(
            source_root=r"C:\Python314",
            manifest_path=authority + r"\python-runtime-manifest.json",
            manifest_sha256="3" * 64,
            destination_root=authority + r"\python-runtime",
        ),
        git_runtime=SealedTreeAuthority(
            source_root=r"C:\Program Files\Git",
            manifest_path=authority + r"\git-runtime-manifest.json",
            manifest_sha256="4" * 64,
            destination_root=authority + r"\git-runtime",
        ),
        repo_evidence_root=r"E:\HMS_AI_Project_Bridge_SOURCE",
        preflight_proof_path=authority + r"\preflight-proof.json",
        stage0_proof_path=authority + r"\stage0-proof.json",
        launcher_proof_path=authority + r"\launcher-proof.json",
        preflight=PreflightAuthority(
            run_dir=r"E:\HMS_AI_Project_Bridge_PROOFS\r002f-run",
            package_root=r"E:\HMS_AI_Project_Bridge_PACKAGE",
            package_manifest=r"E:\HMS_AI_Project_Bridge_PACKAGE\manifest.json",
            runtime_config=r"C:\ProgramData\HMS-GPT-VPS\Bridge\bridge-runtime.json",
            instance_registry=r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\instances.json",
            instance_runtime_dir=r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime",
            bridge_device_credential=r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\device.json",
            trust_root_certificate=r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\ca.pem",
            challenge_source_commit="5" * 40,
            challenge_workspace_path=r"E:\HMS_AI_Project_Bridge_SOURCE",
            challenge_expected_sha256="6" * 64,
            max_reconcile_steps=8,
            external_timeout_seconds=300.0,
            step_timeout_seconds=900.0,
        ),
    )


def test_bundle_roundtrip_is_canonical_and_secret_free() -> None:
    value = bundle()
    data = value.to_bytes()
    restored = R002FExternalDeploymentAuthorityBundle.from_bytes(data)
    assert restored == value
    assert restored.sha256 == value.sha256
    text = data.decode("utf-8")
    assert "HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD" not in text
    assert "HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME" not in text


def test_bundle_rejects_duplicate_json_fields() -> None:
    raw = bundle().to_bytes().decode("utf-8").rstrip()
    tampered = raw[:-1] + ',"reviewed_commit":"' + ("1" * 40) + '"}\n'
    with pytest.raises(R002FExternalDeploymentBundleError, match="duplicate"):
        R002FExternalDeploymentAuthorityBundle.from_bytes(tampered.encode("utf-8"))


def test_bundle_pins_reviewed_launcher_and_stage0_hashes() -> None:
    value = bundle()
    bad = R002FExternalDeploymentAuthorityBundle(
        **{**value.__dict__, "launcher": PinnedArtifact(value.launcher.path, "a" * 64)}
    )
    with pytest.raises(R002FExternalDeploymentBundleError, match="launcher SHA-256"):
        bad.validate()


def test_bundle_requires_direct_child_manifests_and_proofs() -> None:
    value = bundle()
    bad_project = SealedTreeAuthority(
        value.project.source_root,
        value.authority_parent + r"\nested\project.json",
        value.project.manifest_sha256,
        value.project.destination_root,
    )
    bad = R002FExternalDeploymentAuthorityBundle(
        **{**value.__dict__, "project": bad_project}
    )
    with pytest.raises(R002FExternalDeploymentBundleError, match="direct child"):
        bad.validate()


def test_bundle_rejects_nested_destination_or_source_authority_overlap() -> None:
    value = bundle()
    bad_python = SealedTreeAuthority(
        value.python_runtime.source_root,
        value.python_runtime.manifest_path,
        value.python_runtime.manifest_sha256,
        value.project.destination_root + r"\python",
    )
    bad = R002FExternalDeploymentAuthorityBundle(
        **{**value.__dict__, "python_runtime": bad_python}
    )
    with pytest.raises(R002FExternalDeploymentBundleError, match="direct child"):
        bad.validate()


def test_bundle_rejects_nonfinite_or_bool_numeric_fields() -> None:
    value = bundle()
    bad_preflight = PreflightAuthority(
        **{**value.preflight.__dict__, "external_timeout_seconds": float("nan")}
    )
    bad = R002FExternalDeploymentAuthorityBundle(
        **{**value.__dict__, "preflight": bad_preflight}
    )
    with pytest.raises(R002FExternalDeploymentBundleError, match="positive and finite"):
        bad.validate()


def test_rendered_command_externally_pins_launcher_before_child() -> None:
    text = render_os_trusted_launcher_command(bundle())
    assert "[IO.FileShare]::Read" in text
    assert "SHA256" in text
    assert "launcher external SHA-256 mismatch" in text
    assert "[Environment]::SystemDirectory" in text
    assert "powershell.exe" in text
    assert "-LauncherExternalSha256" in text
    assert REVIEWED_LAUNCHER_SHA256 in text
    assert "HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD" not in text
    assert "HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME" not in text


def test_bundle_rejects_option_shaped_challenge_workspace() -> None:
    value = bundle()
    bad_preflight = PreflightAuthority(
        **{**value.preflight.__dict__, "challenge_workspace_path": "--execution-root=x"}
    )
    bad = R002FExternalDeploymentAuthorityBundle(
        **{**value.__dict__, "preflight": bad_preflight}
    )
    with pytest.raises(R002FExternalDeploymentBundleError, match="workspace_path"):
        bad.validate()


def test_bundle_rejects_direct_child_path_aliasing() -> None:
    value = bundle()
    bad = R002FExternalDeploymentAuthorityBundle(
        **{**value.__dict__, "launcher_proof_path": value.project.manifest_path}
    )
    with pytest.raises(R002FExternalDeploymentBundleError, match="must be unique"):
        bad.validate()


def test_bundle_rejects_preflight_path_inside_authority_parent() -> None:
    value = bundle()
    bad_preflight = PreflightAuthority(
        **{
            **value.preflight.__dict__,
            "run_dir": value.authority_parent + r"\run-output",
        }
    )
    bad = R002FExternalDeploymentAuthorityBundle(
        **{**value.__dict__, "preflight": bad_preflight}
    )
    with pytest.raises(
        R002FExternalDeploymentBundleError,
        match="separate from authority_parent",
    ):
        bad.validate()


def test_rendered_command_fails_closed_if_os_powershell_missing() -> None:
    text = render_os_trusted_launcher_command(bundle())
    assert "OS Windows PowerShell missing" in text
    assert "$code=255" in text


def test_bundle_rejects_filesystem_root_authority_parent() -> None:
    value = bundle()
    bad = R002FExternalDeploymentAuthorityBundle(
        **{**value.__dict__, "authority_parent": "C:\\"}
    )
    with pytest.raises(R002FExternalDeploymentBundleError, match="filesystem root"):
        bad.validate()


def test_render_cli_requires_canonical_bundle_digest(tmp_path: Path) -> None:
    value = bundle()
    path = tmp_path / "bundle.json"
    path.write_bytes(value.to_bytes())
    script = ROOT / "scripts" / "render_r002f_external_deployment_command.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--bundle",
            str(path),
            "--bundle-sha256",
            value.sha256,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert REVIEWED_LAUNCHER_SHA256 in result.stdout
    bad = subprocess.run(
        [
            sys.executable,
            str(script),
            "--bundle",
            str(path),
            "--bundle-sha256",
            "0" * 64,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode != 0
    assert "bundle SHA-256 differs" in bad.stderr
