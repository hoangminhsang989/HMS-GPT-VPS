from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from hms_gpt_vps.managed_agent_reconcile_runtime import (
    ManagedAgentReconcileError,
    ManagedAgentReconcileRuntime,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps.provisioning import (
    ProvisionContext,
    ProvisionObservation,
    ProvisioningOrchestrator,
)
from hms_gpt_vps.windows_provisioner import HyperVHostState, WindowsVMConfig


@dataclass(frozen=True)
class DummyConfig:
    instance_id: str = "hms-01"


class DummyAgentRuntime:
    def __init__(self, observation: ProvisionObservation) -> None:
        self.config = DummyConfig()
        self.observation = observation
        self.applied: list[str] = []

    def provision_observation(
        self,
        _credential: PowerShellDirectCredential,
    ) -> ProvisionObservation:
        return self.observation

    def apply(
        self,
        action: str,
        _credential: PowerShellDirectCredential,
    ) -> dict[str, object]:
        self.applied.append(action)
        return {"action": action, "ok": True}


def ready_host() -> HyperVHostState:
    return HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=True,
        virtualization_firmware_enabled=True,
        restart_required=False,
    )


def context(*, base_observation: ProvisionObservation | None = None) -> ProvisionContext:
    return ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=ready_host(),
        image=None,
        observation=base_observation or ProvisionObservation(),
    )


def credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "temporary-secret")


def orchestrator_at(tmp_path: Path, state: ProvisionState) -> ProvisioningOrchestrator:
    state_path = tmp_path / "provision.json"
    ProvisionStateStore(state_path).transition(
        instance_id="hms-01",
        state=state,
    )
    return ProvisioningOrchestrator(state_path)


def test_reconcile_dispatches_stage_without_advancing_state(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_INSTALLING)
    agent = DummyAgentRuntime(ProvisionObservation(agent_package_ready=False))
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]

    result = runtime.reconcile_once(context(), credential())

    assert result.action == "STAGE_HMS_AGENT_PACKAGE"
    assert result.state is ProvisionState.AGENT_INSTALLING
    assert result.mutation_result == {
        "action": "STAGE_HMS_AGENT_PACKAGE",
        "ok": True,
    }
    assert agent.applied == ["STAGE_HMS_AGENT_PACKAGE"]
    assert orchestrator.current("hms-01").state is ProvisionState.AGENT_INSTALLING


def test_reconcile_dispatches_install_only_after_fresh_package_proof(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_INSTALLING)
    agent = DummyAgentRuntime(
        ProvisionObservation(
            agent_package_ready=True,
            agent_service_ready=False,
        )
    )
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]

    result = runtime.reconcile_once(context(), credential())

    assert result.action == "INSTALL_HMS_AGENT"
    assert result.state is ProvisionState.AGENT_INSTALLING
    assert agent.applied == ["INSTALL_HMS_AGENT"]
    assert orchestrator.current("hms-01").state is ProvisionState.AGENT_INSTALLING


def test_service_ready_observation_advances_without_dispatching_mutation(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_INSTALLING)
    agent = DummyAgentRuntime(
        ProvisionObservation(
            agent_package_ready=True,
            agent_service_ready=True,
            agent_healthy=False,
        )
    )
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]

    result = runtime.reconcile_once(context(), credential())

    assert result.action == "AGENT_SERVICE_VERIFIED"
    assert result.state is ProvisionState.AGENT_SERVICE_READY
    assert result.mutation_result is None
    assert agent.applied == []
    assert orchestrator.current("hms-01").state is ProvisionState.AGENT_SERVICE_READY


def test_health_wait_then_health_proof_advances_to_agent_healthy(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_SERVICE_READY)
    agent = DummyAgentRuntime(
        ProvisionObservation(
            agent_package_ready=True,
            agent_service_ready=True,
            agent_healthy=False,
        )
    )
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]

    waiting = runtime.reconcile_once(context(), credential())
    assert waiting.action == "WAIT_FOR_AGENT_APPLICATION_HEALTH"
    assert waiting.state is ProvisionState.AGENT_SERVICE_READY
    assert waiting.mutation_result is None

    agent.observation = ProvisionObservation(
        agent_package_ready=True,
        agent_service_ready=True,
        agent_healthy=True,
    )
    healthy = runtime.reconcile_once(context(), credential())
    assert healthy.action == "AGENT_APPLICATION_HEALTH_VERIFIED"
    assert healthy.state is ProvisionState.AGENT_HEALTHY
    assert healthy.mutation_result is None
    assert agent.applied == []


def test_agent_observation_merge_preserves_unrelated_host_facts(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_INSTALLING)
    agent = DummyAgentRuntime(ProvisionObservation(agent_package_ready=False))
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]
    base = ProvisionObservation(
        network_ready=True,
        vm_id="11111111-2222-3333-4444-555555555555",
        install_media_ready=True,
        vm_running=True,
        guest_booted=True,
        guest_bootstrap_ready=True,
        agent_device_enrolled=True,
    )

    captured: dict[str, ProvisionObservation] = {}
    original_reconcile = orchestrator.reconcile

    def capture(observed_context: ProvisionContext):
        captured["observation"] = observed_context.observation
        return original_reconcile(observed_context)

    orchestrator.reconcile = capture  # type: ignore[method-assign]
    runtime.reconcile_once(context(base_observation=base), credential())

    merged = captured["observation"]
    assert merged.network_ready is True
    assert merged.vm_id == base.vm_id
    assert merged.guest_bootstrap_ready is True
    assert merged.agent_device_enrolled is True
    assert merged.agent_package_ready is False


def test_reconcile_rejects_use_outside_late_agent_states_before_agent_observation(
    tmp_path: Path,
) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.GUEST_BOOTSTRAP)

    class ForbiddenAgentRuntime(DummyAgentRuntime):
        def provision_observation(self, _credential):  # type: ignore[no-untyped-def]
            raise AssertionError("Agent observation must not run from the wrong state")

    agent = ForbiddenAgentRuntime(ProvisionObservation())
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]

    with pytest.raises(ManagedAgentReconcileError, match="not allowed from state"):
        runtime.reconcile_once(context(), credential())


def test_reconcile_rejects_context_for_another_instance(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_INSTALLING)
    agent = DummyAgentRuntime(ProvisionObservation())
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]
    wrong = ProvisionContext(
        instance_id="other-instance",
        config=WindowsVMConfig(),
        host=ready_host(),
        image=None,
    )

    with pytest.raises(ManagedAgentReconcileError, match="context instance"):
        runtime.reconcile_once(wrong, credential())
