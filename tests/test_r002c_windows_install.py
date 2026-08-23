import os
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from hms_gpt_vps.bootstrap_credentials import generate_bootstrap_credential
from hms_gpt_vps.hyperv_vm import build_reconcile_vm_script
from hms_gpt_vps.install_artifacts import prepare_install_artifacts
from hms_gpt_vps.unattend import (
    BootstrapAccount,
    InstallUnattendConfig,
    UNATTEND_NS,
    UnattendConfig,
    generate_install_unattend,
)
from hms_gpt_vps.windows_dpapi import (
    DpapiUnavailableError,
    protect_bytes,
    unprotect_bytes,
)
from hms_gpt_vps.windows_install_start import build_start_unattended_install_script
from hms_gpt_vps.windows_provisioner import WindowsVMConfig


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


def install_config(password: str = "Aa1!0123456789012345678901234567") -> InstallUnattendConfig:
    return InstallUnattendConfig(
        base=UnattendConfig(computer_name="HMSVPS01"),
        bootstrap=BootstrapAccount(username="hmsbootstrap", password=password),
        image_index=1,
        dedicated_blank_disk_acknowledged=True,
    )


def test_bootstrap_credentials_are_random_and_repr_redacted() -> None:
    first = generate_bootstrap_credential()
    second = generate_bootstrap_credential()
    assert first.password != second.password
    assert len(first.password) == 32
    assert first.password not in repr(first)
    assert first.username in repr(first)


def test_unattend_bootstrap_password_is_redacted_from_repr() -> None:
    config = install_config()
    assert config.bootstrap.password not in repr(config.bootstrap)
    assert config.bootstrap.password not in repr(config)
    assert config.bootstrap.username in repr(config.bootstrap)


def test_dpapi_is_windows_only_and_round_trips_when_available() -> None:
    secret = b"hms-transient-secret"
    if os.name == "nt":
        protected = protect_bytes(secret)
        assert protected != secret
        assert unprotect_bytes(protected) == secret
    else:
        with pytest.raises(DpapiUnavailableError):
            protect_bytes(secret)


def test_install_unattend_requires_explicit_blank_disk_acknowledgement() -> None:
    config = InstallUnattendConfig(
        base=UnattendConfig(computer_name="HMSVPS01"),
        bootstrap=BootstrapAccount(
            username="hmsbootstrap",
            password="Aa1!0123456789012345678901234567",
        ),
    )
    with pytest.raises(ValueError, match="WillWipeDisk"):
        generate_install_unattend(config)


def test_full_install_unattend_uses_current_gpt_layout_and_no_product_key() -> None:
    config = install_config()
    xml = generate_install_unattend(config)
    lowered = xml.lower()

    assert "productkey" not in lowered
    assert "pairing" not in lowered
    assert "api_key" not in lowered
    assert "<wipedisk" not in lowered
    assert "<willwipedisk>true</willwipedisk>" in lowered
    assert "<size>300</size>" in lowered
    assert "<type>efi</type>" in lowered
    assert "<type>msr</type>" in lowered
    assert "<size>16</size>" in lowered
    assert "<extend>true</extend>" in lowered
    assert "/image/index" in lowered
    assert "<group>administrators</group>" in lowered
    assert "<logoncount>1</logoncount>" in lowered
    assert "<hideonlineaccountscreens>true</hideonlineaccountscreens>" in lowered
    assert "<hidewirelesssetupinoobe>true</hidewirelesssetupinoobe>" in lowered

    root = ET.fromstring(xml)
    namespace = {"u": UNATTEND_NS}
    passwords = root.findall(".//u:Password/u:Value", namespace)
    assert len(passwords) == 2
    assert all(node.text == config.bootstrap.password for node in passwords)


def test_install_artifact_pipeline_returns_no_password(tmp_path: Path) -> None:
    store = MemorySecretStore()
    credential = generate_bootstrap_credential()
    artifacts = prepare_install_artifacts(
        tmp_path,
        UnattendConfig(computer_name="HMSVPS01"),
        credential=credential,
        secret_store=store,
    )
    assert artifacts.answer_iso.exists()
    assert artifacts.answer_iso_size > 0
    assert len(artifacts.answer_iso_sha256) == 64
    assert credential.password not in repr(artifacts)
    assert credential.password not in artifacts.answer_iso.name
    assert store.value is not None


def test_windows_vm_reconcile_enables_windows11_tpm_baseline() -> None:
    script = build_reconcile_vm_script(WindowsVMConfig())
    assert "Set-VMFirmware" in script
    assert "SecureBootTemplate MicrosoftWindows" in script
    assert "Set-VMKeyProtector" in script
    assert "-NewLocalKeyProtector" in script
    assert "Enable-VMTPM" in script
    assert "Get-VMSecurity" in script


def test_start_install_gate_verifies_single_managed_vhd_media_and_security(tmp_path: Path) -> None:
    windows_iso = tmp_path / "windows.iso"
    answer_iso = tmp_path / "answer.iso"
    script = build_start_unattended_install_script(
        WindowsVMConfig(),
        windows_iso,
        answer_iso,
    )
    assert "$hardDisks.Count -ne 1" in script
    assert "attached VHDX is not the managed target" in script
    assert "complete install bundle is not attached" in script
    assert "Secure Boot is not enabled" in script
    assert "virtual TPM is not enabled" in script
    assert "Start-VM" in script
    assert "Stop-VM" not in script
