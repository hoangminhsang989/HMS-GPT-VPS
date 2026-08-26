from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps.provisioning import (
    ProvisionContext,
    ProvisionObservation,
    ProvisioningOrchestrator,
)


def orchestrator_at(tmp_path: Path, state: ProvisionState) -> ProvisioningOrchestrator:
    path = tmp_path / "provision.json"
    ProvisionStateStore(path).transition(instance_id="hms-01", state=state)
    return ProvisioningOrchestrator(path)


def test_mark_guest_booted_requires_os_installing(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.OS_INSTALLING)
    result = orchestrator.mark_guest_booted("hms-01")
    assert result.state is ProvisionState.GUEST_BOOTED

    with pytest.raises(ValueError, match="expected provision state os_installing"):
        orchestrator.mark_guest_booted("hms-01")
    assert orchestrator.store.load().state is ProvisionState.GUEST_BOOTED  # type: ignore[union-attr]


def test_mark_agent_healthy_requires_service_ready(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_SERVICE_READY)
    result = orchestrator.mark_agent_healthy("hms-01")
    assert result.state is ProvisionState.AGENT_HEALTHY

    with pytest.raises(ValueError, match="expected provision state agent_service_ready"):
        orchestrator.mark_agent_healthy("hms-01")
    assert orchestrator.store.load().state is ProvisionState.AGENT_HEALTHY  # type: ignore[union-attr]


def test_mark_ready_shortcut_is_blocked(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.PAIRING_PENDING)
    with pytest.raises(
        NotImplementedError,
        match="principal-pairing binding authority",
    ):
        orchestrator.mark_ready("hms-01")
    assert orchestrator.store.load().state is ProvisionState.PAIRING_PENDING  # type: ignore[union-attr]


def test_paired_observation_cannot_bypass_durable_principal_binding(
    tmp_path: Path,
) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.PAIRING_PENDING)

    class ValidAuthority:
        def validate(self) -> None:
            return None

    result = orchestrator.reconcile(
        ProvisionContext(
            instance_id="hms-01",
            config=ValidAuthority(),  # type: ignore[arg-type]
            host=ValidAuthority(),  # type: ignore[arg-type]
            image=None,
            observation=ProvisionObservation(
                pairing_ready=True,
                paired=True,
            ),
        )
    )
    assert result.record.state is ProvisionState.PAIRING_PENDING
    assert result.action == "WAIT_FOR_PRINCIPAL_BINDING"
