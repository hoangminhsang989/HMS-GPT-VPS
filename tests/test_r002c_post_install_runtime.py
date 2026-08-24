from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hms_gpt_vps import post_install_runtime as runtime_module
from hms_gpt_vps.post_install_runtime import (
    PostInstallFinalizationConfig,
    PostInstallFinalizationRuntime,
    PostInstallStateError,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps.provisioning import (
    ProvisionContext,
    ProvisionObservation,
    ProvisioningOrchestrator,
)
from hms_gpt_vps.windows_provisioner import HyperVHostState, WindowsVMConfig


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


def ready_host() -> HyperVHostState:
    return HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=True,
        virtualization_firmware_enabled=True,
        restart_required=False,
    )


def context(observation: ProvisionObservation) -> ProvisionContext:
    return ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=ready_host(),
        image=None,
        observation=observation,
    )


def finalization_config(tmp_path: Path, payload: bytes = b"answer-media") -> tuple[PostInstallFinalizationConfig, Path]:
    runtime = tmp_path / "runtime"
    runtime.mkdir(exist_ok=True)
    answer = runtime / "hms-answer.iso"
    answer.write_bytes(payload)
    config = PostInstallFinalizationConfig(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS",
        bootstrap_username="hmsbootstrap",
        answer_iso=answer,
        answer_iso_sha256=hashlib.sha256(payload).hexdigest(),
        runtime_dir=runtime,
    )
    return config, answer


def test_orchestrator_separates_service_readiness_from_application_health(tmp_path: Path) -> None:
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.AGENT_INSTALLING)
    orchestrator = ProvisioningOrchestrator(state_path)

    result = orchestrator.reconcile(
        context(
            ProvisionObservation(
                agent_package_ready=True,
                agent_service_ready=True,
            )
        )
    )
    assert result.record.state is ProvisionState.AGENT_SERVICE_READY
    assert result.action == "AGENT_SERVICE_VERIFIED"

    waiting = orchestrator.reconcile(
        context(ProvisionObservation(agent_service_ready=True, agent_healthy=False))
    )
    assert waiting.record.state is ProvisionState.AGENT_SERVICE_READY
    assert waiting.action == "WAIT_FOR_AGENT_APPLICATION_HEALTH"

    healthy = orchestrator.reconcile(
        context(ProvisionObservation(agent_service_ready=True, agent_healthy=True))
    )
    assert healthy.record.state is ProvisionState.AGENT_HEALTHY
    assert healthy.action == "AGENT_APPLICATION_HEALTH_VERIFIED"


def test_bootstrap_retiring_never_auto_retries_credentialed_action(tmp_path: Path) -> None:
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.BOOTSTRAP_RETIRING)
    orchestrator = ProvisioningOrchestrator(state_path)

    result = orchestrator.reconcile(context(ProvisionObservation()))
    assert result.record.state is ProvisionState.BOOTSTRAP_RETIRING
    assert result.action == "WAIT_FOR_BOOTSTRAP_RETIREMENT_PROOF"
    assert "RETIRE_BOOTSTRAP" not in result.action

    proved = orchestrator.reconcile(
        context(ProvisionObservation(bootstrap_retired=True))
    )
    assert proved.record.state is ProvisionState.BOOTSTRAP_RETIRED
    assert proved.action == "BOOTSTRAP_RETIREMENT_VERIFIED"


def test_retirement_timeout_leaves_fail_closed_checkpoint_and_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.AGENT_HEALTHY)
    config, _ = finalization_config(tmp_path)
    runtime = PostInstallFinalizationRuntime(config, state_path, MemorySecretStore())
    credential = PowerShellDirectCredential("hmsbootstrap", "Aa1!secret")
    calls = {"count": 0}

    def fail_retirement(*args: object, **kwargs: object) -> dict[str, object]:
        calls["count"] += 1
        raise TimeoutError("simulated host crash window")

    monkeypatch.setattr(runtime_module, "retire_bootstrap_guest", fail_retirement)

    with pytest.raises(TimeoutError):
        runtime.retire_bootstrap(credential)
    assert calls["count"] == 1
    current = store.load()
    assert current is not None
    assert current.state is ProvisionState.BOOTSTRAP_RETIRING
    assert current.reason == "retirement_result_unknown_requires_external_proof"

    with pytest.raises(PostInstallStateError, match="AGENT_HEALTHY"):
        runtime.retire_bootstrap(credential)
    assert calls["count"] == 1


def test_external_retirement_proof_resumes_without_bootstrap_credential(tmp_path: Path) -> None:
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.BOOTSTRAP_RETIRING)
    config, _ = finalization_config(tmp_path)
    runtime = PostInstallFinalizationRuntime(config, state_path, MemorySecretStore())

    record = runtime.record_external_retirement_proof()
    assert record.state is ProvisionState.BOOTSTRAP_RETIRED


def test_host_only_detach_and_cleanup_resume_after_retirement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.BOOTSTRAP_RETIRED)
    config, answer = finalization_config(tmp_path)
    secret_store = MemorySecretStore()
    runtime = PostInstallFinalizationRuntime(config, state_path, secret_store)

    detach_calls = {"count": 0}

    def detached(*args: object, **kwargs: object) -> dict[str, object]:
        detach_calls["count"] += 1
        return {"detached": True}

    monkeypatch.setattr(runtime_module, "detach_answer_iso", detached)
    detached_record = runtime.detach_answer_media()
    assert detached_record.state is ProvisionState.ANSWER_MEDIA_DETACHED
    assert detach_calls["count"] == 1

    cleared_record = runtime.clear_transient_install_secrets()
    assert cleared_record.state is ProvisionState.INSTALL_SECRETS_CLEARED
    assert not answer.exists()
    assert secret_store.value is None


def test_cleanup_hash_failure_does_not_advance_or_clear_store(tmp_path: Path) -> None:
    state_path = tmp_path / "provision.json"
    store = ProvisionStateStore(state_path)
    store.transition(instance_id="hms-01", state=ProvisionState.ANSWER_MEDIA_DETACHED)
    config, answer = finalization_config(tmp_path, payload=b"original")
    secret_store = MemorySecretStore()
    runtime = PostInstallFinalizationRuntime(config, state_path, secret_store)

    answer.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="SHA-256 changed"):
        runtime.clear_transient_install_secrets()

    current = store.load()
    assert current is not None
    assert current.state is ProvisionState.ANSWER_MEDIA_DETACHED
    assert answer.exists()
    assert secret_store.value == "protected-bootstrap"


def test_checked_transition_rejects_out_of_order_cleanup(tmp_path: Path) -> None:
    store = ProvisionStateStore(tmp_path / "provision.json")
    store.transition(instance_id="hms-01", state=ProvisionState.AGENT_SERVICE_READY)
    with pytest.raises(ValueError, match="expected provision state"):
        store.transition_checked(
            instance_id="hms-01",
            expected_state=ProvisionState.BOOTSTRAP_RETIRED,
            state=ProvisionState.ANSWER_MEDIA_DETACHED,
        )
