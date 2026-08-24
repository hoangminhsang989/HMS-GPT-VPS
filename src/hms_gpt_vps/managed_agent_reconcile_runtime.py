from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Mapping

from .managed_agent_provisioning_runtime import ManagedAgentProvisioningRuntime
from .powershell_direct import PowerShellDirectCredential
from .provision_state import ProvisionState
from .provisioning import (
    ProvisionContext,
    ProvisionObservation,
    ProvisioningOrchestrator,
    TransitionResult,
)


_LATE_GUEST_STATES = frozenset(
    {
        ProvisionState.AGENT_INSTALLING,
        ProvisionState.AGENT_SERVICE_READY,
    }
)
_MUTATION_ACTIONS = frozenset(
    {
        "STAGE_HMS_AGENT_PACKAGE",
        "INSTALL_HMS_AGENT",
    }
)
_NONMUTATING_ACTIONS = frozenset(
    {
        "AGENT_SERVICE_VERIFIED",
        "WAIT_FOR_AGENT_APPLICATION_HEALTH",
        "AGENT_APPLICATION_HEALTH_VERIFIED",
    }
)


class ManagedAgentReconcileError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManagedAgentReconcileResult:
    transition: TransitionResult
    mutation_result: Mapping[str, object] | None

    @property
    def action(self) -> str:
        return self.transition.action

    @property
    def state(self) -> ProvisionState:
        return self.transition.record.state


class ManagedAgentReconcileRuntime:
    """Bounded one-step wiring for late managed guest Agent provisioning.

    Each call performs one fresh read-only Agent observation, lets the durable
    provisioning orchestrator decide the next action, and dispatches at most one
    approved late-guest mutation. Mutation actions intentionally do not advance
    durable provisioning state in the same call; a later call must re-observe
    the postcondition before the orchestrator may advance.
    """

    def __init__(
        self,
        orchestrator: ProvisioningOrchestrator,
        agent_runtime: ManagedAgentProvisioningRuntime,
    ) -> None:
        self.orchestrator = orchestrator
        self.agent_runtime = agent_runtime
        if agent_runtime.config.instance_id.strip() == "":
            raise ValueError("managed Agent runtime instance_id is required")

    def _current_late_state(self, instance_id: str) -> ProvisionState:
        record = self.orchestrator.current(instance_id)
        if record.instance_id != self.agent_runtime.config.instance_id:
            raise ManagedAgentReconcileError(
                "provision state instance does not match managed Agent runtime"
            )
        if record.state not in _LATE_GUEST_STATES:
            raise ManagedAgentReconcileError(
                f"late Agent reconcile is not allowed from state {record.state.value}"
            )
        return record.state

    @staticmethod
    def _merge_agent_observation(
        base: ProvisionObservation,
        agent: ProvisionObservation,
    ) -> ProvisionObservation:
        """Preserve unrelated host observations while replacing Agent facts."""
        return replace(
            base,
            agent_package_ready=agent.agent_package_ready,
            agent_service_ready=agent.agent_service_ready,
            agent_healthy=agent.agent_healthy,
        )

    def reconcile_once(
        self,
        context: ProvisionContext,
        credential: PowerShellDirectCredential,
    ) -> ManagedAgentReconcileResult:
        credential.validate()
        if context.instance_id != self.agent_runtime.config.instance_id:
            raise ManagedAgentReconcileError(
                "provision context instance does not match managed Agent runtime"
            )
        self._current_late_state(context.instance_id)

        agent_observation = self.agent_runtime.provision_observation(credential)
        observed_context = replace(
            context,
            observation=self._merge_agent_observation(
                context.observation,
                agent_observation,
            ),
        )
        transition = self.orchestrator.reconcile(observed_context)

        if transition.action in _MUTATION_ACTIONS:
            # The orchestrator must not advance durable state merely because a
            # mutation was attempted. Re-observation on a later call is the gate.
            if transition.record.state is not ProvisionState.AGENT_INSTALLING:
                raise ManagedAgentReconcileError(
                    "late Agent mutation action escaped AGENT_INSTALLING checkpoint"
                )
            result = self.agent_runtime.apply(transition.action, credential)
            if not isinstance(result, dict):
                raise ManagedAgentReconcileError(
                    "managed Agent mutation result must be an object"
                )
            return ManagedAgentReconcileResult(transition, result)

        if transition.action in _NONMUTATING_ACTIONS:
            return ManagedAgentReconcileResult(transition, None)

        raise ManagedAgentReconcileError(
            f"unexpected action in late Agent reconcile boundary: {transition.action}"
        )
