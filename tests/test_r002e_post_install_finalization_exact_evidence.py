from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hms_gpt_vps import bootstrap_retirement as retirement_module
from hms_gpt_vps import post_install_runtime as runtime_module
from hms_gpt_vps.bootstrap_retirement import (
    build_detach_answer_iso_script,
    detach_answer_iso,
    retire_bootstrap_guest,
)
from hms_gpt_vps.post_install_runtime import (
    PostInstallFinalizationConfig,
    PostInstallFinalizationRuntime,
    PostInstallStateError,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore


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
    )
    with pytest.raises(ValueError, match="link or reparse"):
        config.validate()
