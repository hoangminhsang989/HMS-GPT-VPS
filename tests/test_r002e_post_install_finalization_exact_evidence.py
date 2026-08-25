from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path

import pytest

from hms_gpt_vps import bootstrap_retirement as retirement_module
from hms_gpt_vps import post_install_runtime as runtime_module
from hms_gpt_vps.bootstrap_retirement import (
    build_detach_answer_iso_by_id_script,
    build_detach_answer_iso_script,
    detach_answer_iso,
    detach_answer_iso_by_id,
    retire_bootstrap_guest,
    retire_bootstrap_guest_by_id,
)
from hms_gpt_vps.post_install_runtime import (
    PostInstallFinalizationConfig,
    PostInstallFinalizationRuntime,
    PostInstallStateError,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore


_MANAGED_VM_ID = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
_OTHER_VM_ID = "cccccccc-4444-5555-6666-dddddddddddd"


class MemorySecretStore:
    def __init__(self, value: str = "protected-bootstrap") -> None:
        self.value: str | None = value

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("secret missing")
        return self.value

    def clear(self) -> None:
        self.value = None


def _credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "Aa1!secret")


def _retirement_payload() -> dict[str, object]:
    return {
        "retired": True,
        "bootstrap_user": "hmsbootstrap",
        "account_disabled": True,
        "autologon_disabled": True,
        "default_password_absent": True,
        "removed_unattend_count": 0,
    }


def _finalization_config(tmp_path: Path) -> tuple[PostInstallFinalizationConfig, Path]:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    answer = runtime / "hms-answer.iso"
    payload = b"answer-media"
    answer.write_bytes(payload)
    return (
        PostInstallFinalizationConfig(
            instance_id="hms-01",
            vm_name="HMS-GPT-VPS",
            bootstrap_username="hmsbootstrap",
            answer_iso=answer,
            answer_iso_sha256=hashlib.sha256(payload).hexdigest(),
            runtime_dir=runtime,
            vm_id=_MANAGED_VM_ID,
        ),
        answer,
    )


@pytest.mark.parametrize("bad_retired", ["false", 1, 0, None, False])
def test_retirement_wrapper_requires_exact_true(
    monkeypatch: pytest.MonkeyPatch,
    bad_retired: object,
) -> None:
    payload = _retirement_payload()
    payload["retired"] = bad_retired
    monkeypatch.setattr(
        retirement_module,
        "run_vm_powershell_json",
        lambda *args, **kwargs: payload,
    )
    with pytest.raises(RuntimeError, match="retirement postcondition"):
        retire_bootstrap_guest("HMS-GPT-VPS", _credential(), "hmsbootstrap")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("account_disabled", "true"),
        ("autologon_disabled", 1),
        ("default_password_absent", None),
    ],
)
def test_retirement_wrapper_requires_exact_boolean_postconditions(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: object,
) -> None:
    payload = _retirement_payload()
    payload[key] = value
    monkeypatch.setattr(
        retirement_module,
        "run_vm_powershell_json",
        lambda *args, **kwargs: payload,
    )
    with pytest.raises(RuntimeError, match="did not prove exact"):
        retire_bootstrap_guest("HMS-GPT-VPS", _credential(), "hmsbootstrap")


def test_retirement_wrapper_rejects_schema_user_and_count_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases: list[tuple[dict[str, object], str]] = []

    extra = _retirement_payload()
    extra["extra"] = True
    cases.append((extra, "schema"))

    wrong_user = _retirement_payload()
    wrong_user["bootstrap_user"] = "other"
    cases.append((wrong_user, "user differs"))

    bool_count = _retirement_payload()
    bool_count["removed_unattend_count"] = True
    cases.append((bool_count, "removed_unattend_count"))

    for payload, message in cases:
        monkeypatch.setattr(
            retirement_module,
            "run_vm_powershell_json",
            lambda *args, _payload=payload, **kwargs: _payload,
        )
        with pytest.raises(RuntimeError, match=message):
            retire_bootstrap_guest("HMS-GPT-VPS", _credential(), "hmsbootstrap")


@pytest.mark.parametrize("timeout", [True, 0, 601, 1.5, "90"])
def test_retirement_wrapper_rejects_invalid_timeout(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        retire_bootstrap_guest(
            "HMS-GPT-VPS",
            _credential(),
            "hmsbootstrap",
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


def test_retirement_by_id_binds_powershell_direct_to_canonical_vm_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> dict[str, object]:
        observed["vm_name"] = args[0]
        observed["vm_id"] = kwargs.get("vm_id")
        return _retirement_payload()

    monkeypatch.setattr(retirement_module, "run_vm_powershell_json", fake_run)
    result = retire_bootstrap_guest_by_id(
        _MANAGED_VM_ID,
        "HMS-GPT-VPS",
        _credential(),
        "hmsbootstrap",
    )
    assert result["retired"] is True
    assert observed == {"vm_name": "HMS-GPT-VPS", "vm_id": _MANAGED_VM_ID}


@pytest.mark.parametrize("bad_vm_id", ["", "not-a-guid", _MANAGED_VM_ID.upper()])
def test_retirement_by_id_rejects_noncanonical_vm_id(bad_vm_id: str) -> None:
    with pytest.raises(ValueError, match="VMId"):
        retire_bootstrap_guest_by_id(
            bad_vm_id,
            "HMS-GPT-VPS",
            _credential(),
            "hmsbootstrap",
        )


@pytest.mark.parametrize("bad_detached", ["false", 1, 0, None, False])
def test_detach_wrapper_requires_exact_true_and_path_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad_detached: object,
) -> None:
    answer = tmp_path / "hms-answer.iso"
    expected = str(answer.expanduser().absolute())
    monkeypatch.setattr(
        retirement_module,
        "run_powershell_json",
        lambda *args, **kwargs: {
            "detached": bad_detached,
            "answer_iso": expected,
        },
    )
    with pytest.raises(RuntimeError, match="detach postcondition"):
        detach_answer_iso("HMS-GPT-VPS", answer)


def test_detach_wrapper_rejects_schema_and_path_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answer = tmp_path / "hms-answer.iso"
    expected = str(answer.expanduser().absolute())

    monkeypatch.setattr(
        retirement_module,
        "run_powershell_json",
        lambda *args, **kwargs: {
            "detached": True,
            "answer_iso": expected,
            "extra": True,
        },
    )
    with pytest.raises(RuntimeError, match="schema"):
        detach_answer_iso("HMS-GPT-VPS", answer)

    monkeypatch.setattr(
        retirement_module,
        "run_powershell_json",
        lambda *args, **kwargs: {
            "detached": True,
            "answer_iso": str(tmp_path / "other.iso"),
        },
    )
    with pytest.raises(RuntimeError, match="path differs"):
        detach_answer_iso("HMS-GPT-VPS", answer)


def test_detach_by_id_script_uses_exact_vm_object(tmp_path: Path) -> None:
    answer = tmp_path / "hms-answer.iso"
    script = build_detach_answer_iso_by_id_script(
        _MANAGED_VM_ID,
        "HMS-GPT-VPS",
        answer,
    )
    assert "Get-VM -Id $vmId" in script
    assert "Get-VMDvdDrive -VM $managedVm" in script
    assert "Get-VMDvdDrive -VMName" not in script
    assert "$managedVm.Id.ToString().ToLowerInvariant()" in script


def test_detach_by_id_rejects_wrong_vm_id_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answer = tmp_path / "hms-answer.iso"
    expected = str(answer.expanduser().absolute())
    monkeypatch.setattr(
        retirement_module,
        "run_powershell_json",
        lambda *args, **kwargs: {
            "detached": True,
            "answer_iso": expected,
            "vm_id": _OTHER_VM_ID,
        },
    )
    with pytest.raises(RuntimeError, match="VMId differs"):
        detach_answer_iso_by_id(
            _MANAGED_VM_ID,
            "HMS-GPT-VPS",
            answer,
        )


def test_detach_by_id_accepts_exact_vm_id_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answer = tmp_path / "hms-answer.iso"
    expected = str(answer.expanduser().absolute())
    monkeypatch.setattr(
        retirement_module,
        "run_powershell_json",
        lambda *args, **kwargs: {
            "detached": True,
            "answer_iso": expected,
            "vm_id": _MANAGED_VM_ID,
        },
    )
    result = detach_answer_iso_by_id(
        _MANAGED_VM_ID,
        "HMS-GPT-VPS",
        answer,
    )
    assert result["detached"] is True
    assert result["vm_id"] == _MANAGED_VM_ID


def test_post_install_runtime_does_not_advance_on_truthy_retirement_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _ = _finalization_config(tmp_path)
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.AGENT_HEALTHY)
    runtime = PostInstallFinalizationRuntime(config, state_path, MemorySecretStore())

    monkeypatch.setattr(
        runtime_module,
        "retire_bootstrap_guest",
        lambda *args, **kwargs: {"retired": "false"},
    )
    with pytest.raises(PostInstallStateError, match="postcondition"):
        runtime.retire_bootstrap(_credential())

    current = store.load()
    assert current is not None
    assert current.state is ProvisionState.BOOTSTRAP_RETIRING


def test_post_install_runtime_does_not_advance_on_truthy_detach_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _ = _finalization_config(tmp_path)
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.BOOTSTRAP_RETIRED)
    runtime = PostInstallFinalizationRuntime(config, state_path, MemorySecretStore())

    monkeypatch.setattr(
        runtime_module,
        "detach_answer_iso",
        lambda *args, **kwargs: {"detached": "false"},
    )
    with pytest.raises(PostInstallStateError, match="detach postcondition"):
        runtime.detach_answer_media()

    current = store.load()
    assert current is not None
    assert current.state is ProvisionState.BOOTSTRAP_RETIRED


def test_post_install_runtime_passes_exact_vm_id_to_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _ = _finalization_config(tmp_path)
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.AGENT_HEALTHY)
    runtime = PostInstallFinalizationRuntime(config, state_path, MemorySecretStore())
    observed: dict[str, tuple[object, ...]] = {}

    def retired(*args: object, **kwargs: object) -> dict[str, object]:
        observed["retire"] = args
        return _retirement_payload()

    monkeypatch.setattr(runtime_module, "retire_bootstrap_guest", retired)
    record = runtime.retire_bootstrap(_credential())
    assert record.state is ProvisionState.BOOTSTRAP_RETIRED
    assert observed["retire"][0] == _MANAGED_VM_ID
    assert observed["retire"][1] == "HMS-GPT-VPS"

    def detached(*args: object, **kwargs: object) -> dict[str, object]:
        observed["detach"] = args
        return {"detached": True, "vm_id": _MANAGED_VM_ID}

    monkeypatch.setattr(runtime_module, "detach_answer_iso", detached)
    detached_record = runtime.detach_answer_media()
    assert detached_record.state is ProvisionState.ANSWER_MEDIA_DETACHED
    assert observed["detach"][0] == _MANAGED_VM_ID
    assert observed["detach"][1] == "HMS-GPT-VPS"


def test_finalization_config_requires_canonical_vm_id(tmp_path: Path) -> None:
    config, _ = _finalization_config(tmp_path)
    for bad_vm_id in ("", "not-a-guid", _MANAGED_VM_ID.upper()):
        with pytest.raises(ValueError, match="vm_id"):
            replace(config, vm_id=bad_vm_id).validate()


def test_detach_authority_rejects_symlinked_answer_or_parent(tmp_path: Path) -> None:
    real_runtime = tmp_path / "real-runtime"
    real_runtime.mkdir()
    answer = real_runtime / "hms-answer.iso"
    answer.write_bytes(b"answer")

    direct_link = tmp_path / "answer-link.iso"
    try:
        direct_link.symlink_to(answer)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="link or reparse"):
        build_detach_answer_iso_script("HMS-GPT-VPS", direct_link)

    parent_link = tmp_path / "runtime-link"
    try:
        parent_link.symlink_to(real_runtime, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation unavailable")
    with pytest.raises(ValueError, match="link or reparse"):
        build_detach_answer_iso_script(
            "HMS-GPT-VPS",
            parent_link / "hms-answer.iso",
        )


def test_finalization_config_rejects_symlinked_runtime_authority(tmp_path: Path) -> None:
    real_runtime = tmp_path / "real-runtime"
    real_runtime.mkdir()
    answer = real_runtime / "hms-answer.iso"
    payload = b"answer"
    answer.write_bytes(payload)
    runtime_link = tmp_path / "runtime-link"
    try:
        runtime_link.symlink_to(real_runtime, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation unavailable")

    config = PostInstallFinalizationConfig(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS",
        bootstrap_username="hmsbootstrap",
        answer_iso=runtime_link / "hms-answer.iso",
        answer_iso_sha256=hashlib.sha256(payload).hexdigest(),
        runtime_dir=runtime_link,
        vm_id=_MANAGED_VM_ID,
    )
    with pytest.raises(ValueError, match="link or reparse"):
        config.validate()
