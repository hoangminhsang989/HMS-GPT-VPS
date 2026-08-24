from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps.provisioning import ProvisioningOrchestrator


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


def test_mark_ready_requires_pairing_pending(tmp_path: Path) -> None:
    orchestrator = orchestrator_at(tmp_path, ProvisionState.PAIRING_PENDING)
    result = orchestrator.mark_ready("hms-01")
    assert result.state is ProvisionState.READY

    with pytest.raises(ValueError, match="expected provision state pairing_pending"):
        orchestrator.mark_ready("hms-01")
    assert orchestrator.store.load().state is ProvisionState.READY  # type: ignore[union-attr]
