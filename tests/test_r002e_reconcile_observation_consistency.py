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


class ContradictoryAgentRuntime:
    def __init__(self, observation: ProvisionObservation) -> None:
        self.config = DummyConfig()
        self.observation = observation
        self.observation_called = False
        self.apply_called = False

    def provision_observation(self, _credential):  # type: ignore[no-untyped-def]
        self.observation_called = True
        return self.observation

    def apply(self, _action, _credential):  # type: ignore[no-untyped-def]
        self.apply_called = True
        raise AssertionError("contradictory observation must fail before mutation")


def context() -> ProvisionContext:
    return ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=HyperVHostState(
            is_windows=True,
            hyperv_available=True,
            hyperv_enabled=True,
            virtualization_firmware_enabled=True,
            restart_required=False,
        ),
        image=None,
    )


def credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "temporary-secret")


def orchestrator_at(tmp_path: Path, state: ProvisionState) -> ProvisioningOrchestrator:
    path = tmp_path / "provision.json"
    ProvisionStateStore(path).transition(instance_id="hms-01", state=state)
    return ProvisioningOrchestrator(path)


@pytest.mark.parametrize(
    ("state", "observation", "message"),
    [
        (
            ProvisionState.AGENT_INSTALLING,
            ProvisionObservation(
                agent_package_ready=False,
                agent_service_ready=True,
                agent_healthy=False,
            ),
            "service readiness without package readiness",
        ),
        (
            ProvisionState.AGENT_SERVICE_READY,
            ProvisionObservation(
                agent_package_ready=True,
                agent_service_ready=False,
                agent_healthy=True,
            ),
            "health without service readiness",
        ),
    ],
)
def test_contradictory_agent_observation_fails_before_state_advance_or_mutation(
    tmp_path: Path,
    state: ProvisionState,
    observation: ProvisionObservation,
    message: str,
) -> None:
    orchestrator = orchestrator_at(tmp_path, state)
    agent = ContradictoryAgentRuntime(observation)
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]

    with pytest.raises(ManagedAgentReconcileError, match=message):
        runtime.reconcile_once(context(), credential())

    assert orchestrator.current("hms-01").state is state
    assert agent.observation_called is True
    assert agent.apply_called is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_package_ready", "false"),
        ("agent_service_ready", 1),
        ("agent_healthy", None),
    ],
)
def test_malformed_agent_observation_types_fail_before_orchestrator(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_INSTALLING)
    values: dict[str, object] = {
        "agent_package_ready": False,
        "agent_service_ready": False,
        "agent_healthy": False,
    }
    values[field] = value
    observation = ProvisionObservation(**values)  # type: ignore[arg-type]
    agent = ContradictoryAgentRuntime(observation)
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]

    with pytest.raises(ManagedAgentReconcileError, match=f"boolean evidence: {field}"):
        runtime.reconcile_once(context(), credential())

    assert orchestrator.current("hms-01").state is ProvisionState.AGENT_INSTALLING
    assert agent.apply_called is False


def test_missing_checkpoint_fails_without_creating_state_or_observing_agent(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "missing-provision.json"
    orchestrator = ProvisioningOrchestrator(state_path)
    agent = ContradictoryAgentRuntime(ProvisionObservation())
    runtime = ManagedAgentReconcileRuntime(orchestrator, agent)  # type: ignore[arg-type]

    with pytest.raises(ManagedAgentReconcileError, match="existing provisioning checkpoint"):
        runtime.reconcile_once(context(), credential())

    assert not state_path.exists()
    assert orchestrator.store.load() is None
    assert agent.observation_called is False
    assert agent.apply_called is False
