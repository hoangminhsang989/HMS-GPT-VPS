from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import (
    build_agent_package_manifest,
    verify_agent_package,
)
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.agent_service_readiness import (
    build_agent_service_readiness_script,
    require_agent_service_ready,
)
from hms_gpt_vps.bootstrap_retirement import (
    build_detach_answer_iso_script,
    build_retire_bootstrap_guest_script,
)
from hms_gpt_vps.install_artifacts import clear_install_secrets


class MemorySecretStore:
    def __init__(self, value: str = "secret") -> None:
        self.value: str | None = value

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("secret missing")
        return self.value

    def clear(self) -> None:
        self.value = None


def test_agent_package_manifest_detects_tamper(tmp_path: Path) -> None:
    artifact = tmp_path / "hms-agent.exe"
    artifact.write_bytes(b"agent-v1")
    manifest = build_agent_package_manifest(artifact, version="0.1.0")
    assert manifest.filename == "hms-agent.exe"
    assert manifest.size == len(b"agent-v1")
    verify_agent_package(artifact, manifest)

    artifact.write_bytes(b"agent-v1-tampered")
    with pytest.raises(ValueError, match="size|SHA-256"):
        verify_agent_package(artifact, manifest)


def test_service_readiness_is_not_application_health() -> None:
    script = build_agent_service_readiness_script(
        AgentServiceConfig(),
        expected_sha256="a" * 64,
    )
    assert "application_health = 'NOT_IMPLEMENTED'" in script
    assert "NT AUTHORITY\\LocalService" in script
    assert "qsidtype" in script
    assert "ReadAndExecute" in script
    assert "FileSystemRights]::Modify" in script
    assert "Get-FileHash" in script

    require_agent_service_ready({"service_ready": True})
    with pytest.raises(RuntimeError, match="service readiness"):
        require_agent_service_ready({"service_ready": False})


def test_bootstrap_retirement_disables_account_without_deleting_it() -> None:
    script = build_retire_bootstrap_guest_script("hmsbootstrap")
    assert "Disable-LocalUser" in script
    assert "Remove-LocalUser" not in script
    assert "DefaultPassword" in script
    assert "AutoAdminLogon" in script
    assert "[regex]::Escape($bootstrapUser)" in script
    assert "removed_unattend_count" in script


def test_answer_iso_detach_targets_only_managed_media(tmp_path: Path) -> None:
    answer_iso = tmp_path / "hms-answer.iso"
    script = build_detach_answer_iso_script("HMS-GPT-VPS", answer_iso)
    assert "Where-Object { $_.Path -eq $answerIso }" in script
    assert "Set-VMDvdDrive" in script
    assert "Remove-VMDvdDrive" not in script
    assert "Remove-VM" not in script


def test_secret_cleanup_requires_managed_path_and_matching_hash(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    answer = runtime / "hms-answer.iso"
    payload = b"managed-secret-answer-media"
    answer.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()
    store = MemorySecretStore()

    clear_install_secrets(
        answer,
        store,
        expected_sha256=expected,
        runtime_dir=runtime,
    )
    assert not answer.exists()
    assert store.value is None


def test_secret_cleanup_fails_closed_on_tamper_or_outside_path(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    answer = runtime / "hms-answer.iso"
    answer.write_bytes(b"tampered")
    store = MemorySecretStore()

    with pytest.raises(ValueError, match="SHA-256 changed"):
        clear_install_secrets(
            answer,
            store,
            expected_sha256="0" * 64,
            runtime_dir=runtime,
        )
    assert answer.exists()
    assert store.value == "secret"

    outside = tmp_path / "outside.iso"
    outside.write_bytes(b"outside")
    outside_hash = hashlib.sha256(b"outside").hexdigest()
    with pytest.raises(ValueError, match="outside the managed runtime"):
        clear_install_secrets(
            outside,
            store,
            expected_sha256=outside_hash,
            runtime_dir=runtime,
        )
    assert outside.exists()
    assert store.value == "secret"
