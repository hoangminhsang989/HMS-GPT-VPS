from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread

from hms_gpt_vps.managed_agent_reconcile_runtime import ManagedAgentReconcileRuntime
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


class SharedAgentRuntime:
    def __init__(self) -> None:
        self.config = DummyConfig()
        self.package_ready = False
        self.service_ready = False
        self.observation_count = 0
        self.actions: list[str] = []
        self.stage_entered = Event()
        self.release_stage = Event()
        self._guard = Lock()
        self._active_mutations = 0
        self.max_active_mutations = 0

    def provision_observation(self, _credential):  # type: ignore[no-untyped-def]
        with self._guard:
            self.observation_count += 1
            package_ready = self.package_ready
            service_ready = self.service_ready
        return ProvisionObservation(
            agent_package_ready=package_ready,
            agent_service_ready=service_ready,
            agent_healthy=False,
        )

    def apply(self, action, _credential):  # type: ignore[no-untyped-def]
        with self._guard:
            self.actions.append(action)
            self._active_mutations += 1
            self.max_active_mutations = max(
                self.max_active_mutations,
                self._active_mutations,
            )
        try:
            if action == "STAGE_HMS_AGENT_PACKAGE":
                self.stage_entered.set()
                assert self.release_stage.wait(2)
                with self._guard:
                    self.package_ready = True
                return {"package_ready": True}
            if action == "INSTALL_HMS_AGENT":
                with self._guard:
                    self.service_ready = True
                return {"ready": True}
            raise AssertionError(f"unexpected action: {action}")
        finally:
            with self._guard:
                self._active_mutations -= 1


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


def test_late_reconcile_serializes_observe_decide_mutate_across_runtimes(tmp_path: Path) -> None:
    state_path = tmp_path / "provision.json"
    ProvisionStateStore(state_path).transition(
        instance_id="hms-01",
        state=ProvisionState.AGENT_INSTALLING,
    )
    agent = SharedAgentRuntime()
    first = ManagedAgentReconcileRuntime(
        ProvisioningOrchestrator(state_path),
        agent,  # type: ignore[arg-type]
    )
    second = ManagedAgentReconcileRuntime(
        ProvisioningOrchestrator(state_path),
        agent,  # type: ignore[arg-type]
    )
    outcomes: dict[str, object] = {}
    second_done = Event()

    def run_first() -> None:
        outcomes["first"] = first.reconcile_once(context(), credential())

    def run_second() -> None:
        try:
            outcomes["second"] = second.reconcile_once(context(), credential())
        finally:
            second_done.set()

    thread_first = Thread(target=run_first)
    thread_first.start()
    assert agent.stage_entered.wait(2)
    assert agent.observation_count == 1

    thread_second = Thread(target=run_second)
    thread_second.start()
    assert not second_done.wait(0.15)
    # The contender must not even re-observe until the first mutation exits.
    assert agent.observation_count == 1
    assert agent.actions == ["STAGE_HMS_AGENT_PACKAGE"]

    agent.release_stage.set()
    thread_first.join(timeout=2)
    thread_second.join(timeout=2)
    assert not thread_first.is_alive()
    assert not thread_second.is_alive()

    first_result = outcomes["first"]
    second_result = outcomes["second"]
    assert first_result.action == "STAGE_HMS_AGENT_PACKAGE"  # type: ignore[union-attr]
    assert second_result.action == "INSTALL_HMS_AGENT"  # type: ignore[union-attr]
    assert agent.observation_count == 2
    assert agent.actions == ["STAGE_HMS_AGENT_PACKAGE", "INSTALL_HMS_AGENT"]
    assert agent.max_active_mutations == 1
    assert first.reconcile_lock_path == second.reconcile_lock_path
