from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hms_gpt_vps import windows_install_runtime as runtime_module
from hms_gpt_vps import windows_install_start as start_module
from hms_gpt_vps.hyperv_network import HyperVNetworkConfig
from hms_gpt_vps.hyperv_observe import HyperVObservation
from hms_gpt_vps.install_bundle_observe import InstallBundleState
from hms_gpt_vps.windows_image import WindowsImage
from hms_gpt_vps.windows_install_runtime import (
    WindowsInstallObservation,
    WindowsInstallRuntime,
    WindowsInstallRuntimeConfig,
)
from hms_gpt_vps.windows_install_start import (
    build_start_unattended_install_script,
    start_unattended_install,
)
from hms_gpt_vps.windows_provisioner import WindowsVMConfig


WINDOWS_HASH = "a" * 64
ANSWER_HASH = "b" * 64


def test_start_script_locks_verified_media_until_running() -> None:
    script = build_start_unattended_install_script(
        WindowsVMConfig(),
        Path(r"C:\media\windows.iso"),
        Path(r"C:\media\answer.iso"),
        expected_windows_sha256=WINDOWS_HASH,
        expected_answer_sha256=ANSWER_HASH,
    )

    assert "[System.IO.FileShare]::Read" in script
    assert "Get-HmsLockedStreamSha256" in script
    assert WINDOWS_HASH in script
    assert ANSWER_HASH in script
    assert script.index("$windowsHandle = [System.IO.File]::Open") < script.index("Start-VM -Name $vmName")
    assert script.index("$answerHandle = [System.IO.File]::Open") < script.index("Start-VM -Name $vmName")
    assert script.index("Start-VM -Name $vmName") < script.index("$answerHandle.Dispose()")
    assert "media_lock_held_until_running = [bool]$true" in script


def _start_payload(*, answer_hash: str = ANSWER_HASH) -> dict[str, object]:
    return {
        "changed": True,
        "vm_id": "11111111-2222-3333-4444-555555555555",
        "vm_state": "Running",
        "managed_vhd": r"C:\ProgramData\HMS-GPT-VPS\VMs\HMS-GPT-VPS-01\HMS-GPT-VPS-01.vhdx",
        "windows_iso": r"C:\media\windows.iso",
        "answer_iso": r"C:\media\answer.iso",
        "windows_iso_sha256": WINDOWS_HASH,
        "answer_iso_sha256": answer_hash,
        "media_lock_held_until_running": True,
    }


def test_start_wrapper_rejects_locked_answer_hash_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        start_module,
        "run_powershell_json",
        lambda *args, **kwargs: _start_payload(answer_hash="c" * 64),
    )

    with pytest.raises(RuntimeError, match="answer ISO hash differs"):
        start_unattended_install(
            WindowsVMConfig(),
            Path(r"C:\media\windows.iso"),
            Path(r"C:\media\answer.iso"),
            expected_windows_sha256=WINDOWS_HASH,
            expected_answer_sha256=ANSWER_HASH,
        )


def test_start_wrapper_accepts_exact_locked_hash_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        start_module,
        "run_powershell_json",
        lambda *args, **kwargs: _start_payload(),
    )

    result = start_unattended_install(
        WindowsVMConfig(),
        Path(r"C:\media\windows.iso"),
        Path(r"C:\media\answer.iso"),
        expected_windows_sha256=WINDOWS_HASH,
        expected_answer_sha256=ANSWER_HASH,
    )

    assert result["media_lock_held_until_running"] is True


def test_windows_install_runtime_passes_durable_media_digests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows_iso = tmp_path / "windows.iso"
    answer_iso = tmp_path / "answer.iso"
    windows_iso.write_bytes(b"windows-media")
    answer_iso.write_bytes(b"answer-media")
    windows_hash = hashlib.sha256(windows_iso.read_bytes()).hexdigest()
    answer_hash = hashlib.sha256(answer_iso.read_bytes()).hexdigest()

    config = WindowsInstallRuntimeConfig(
        instance_id="hms-01",
        vm=WindowsVMConfig(),
        network=HyperVNetworkConfig(),
        windows_image=WindowsImage(windows_iso, windows_hash),
        answer_iso=answer_iso,
        answer_iso_sha256=answer_hash,
    )
    runtime = WindowsInstallRuntime(config, tmp_path / "instances.json")
    observed = WindowsInstallObservation(
        hyperv=HyperVObservation(
            network_ready=True,
            vm_id="11111111-2222-3333-4444-555555555555",
            vm_state="Running",
            vm_switch_ready=True,
            install_media_ready=True,
            guest_heartbeat_ok=False,
            secure_boot_enabled=True,
            tpm_enabled=True,
        ),
        bundle=InstallBundleState(True, True, True),
    )
    monkeypatch.setattr(runtime, "observe", lambda: observed)

    captured: dict[str, object] = {}

    def fake_start(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(runtime_module, "start_unattended_install", fake_start)

    runtime.apply("START_UNATTENDED_INSTALL")

    assert captured["expected_windows_sha256"] == windows_hash
    assert captured["expected_answer_sha256"] == answer_hash
