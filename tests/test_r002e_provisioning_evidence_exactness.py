from __future__ import annotations

from dataclasses import replace
import inspect
from pathlib import Path

import pytest

from hms_gpt_vps.provisioning import (
    ProvisionContext,
    ProvisionObservation,
    ProvisioningOrchestrator,
)
from hms_gpt_vps.windows_provisioner import HyperVHostState, WindowsVMConfig, build_provision_plan


def valid_host() -> HyperVHostState:
    return HyperVHostState(
        is_windows=True,
        hyperv_available=True,
        hyperv_enabled=True,
        virtualization_firmware_enabled=True,
        restart_required=False,
    )


def context(*, host: HyperVHostState | None = None, observation: ProvisionObservation | None = None) -> ProvisionContext:
    return ProvisionContext(
        instance_id="hms-01",
        config=WindowsVMConfig(),
        host=host or valid_host(),
        image=None,
        observation=observation or ProvisionObservation(),
    )


@pytest.mark.parametrize(
    "field",
    [
        "network_ready",
        "install_media_ready",
        "vm_running",
        "guest_booted",
        "guest_bootstrap_ready",
        "agent_device_enrolled",
        "agent_package_ready",
        "agent_service_ready",
        "agent_healthy",
        "bootstrap_retired",
        "answer_media_detached",
        "install_secrets_cleared",
        "pairing_ready",
        "paired",
    ],
)
def test_provision_observation_rejects_truthy_non_boolean_fields(field: str) -> None:
    observation = replace(ProvisionObservation(), **{field: "false"})
    with pytest.raises(ValueError, match=field):
        observation.validate()


@pytest.mark.parametrize(
    "vm_id",
    [
        "",
        "vm-id",
        "11111111-2222-3333-4444-55555555555Z",
        "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
    ],
)
def test_provision_observation_rejects_invalid_vm_id_shape(vm_id: str) -> None:
    with pytest.raises(ValueError, match="vm_id"):
        ProvisionObservation(vm_id=vm_id).validate()


def test_provision_observation_rejects_non_string_vm_id() -> None:
    with pytest.raises(ValueError, match="vm_id"):
        ProvisionObservation(vm_id=True).validate()  # type: ignore[arg-type]


def test_provision_observation_accepts_canonical_vm_id() -> None:
    ProvisionObservation(
        vm_id="11111111-2222-3333-4444-555555555555"
    ).validate()


@pytest.mark.parametrize(
    "field",
    [
        "is_windows",
        "hyperv_available",
        "hyperv_enabled",
        "virtualization_firmware_enabled",
        "restart_required",
    ],
)
def test_hyperv_host_state_rejects_truthy_non_boolean_fields(field: str) -> None:
    host = replace(valid_host(), **{field: "false"})
    with pytest.raises(ValueError, match=field):
        host.validate()
    with pytest.raises(ValueError, match=field):
        build_provision_plan(host, WindowsVMConfig())


def test_orchestrator_rejects_malformed_evidence_before_state_creation(tmp_path: Path) -> None:
    state_path = tmp_path / "provision.json"
    orchestrator = ProvisioningOrchestrator(state_path)
    malformed = ProvisionObservation(network_ready="false")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="network_ready"):
        orchestrator.reconcile(context(observation=malformed))

    assert not state_path.exists()


def test_orchestrator_rejects_malformed_host_before_state_creation(tmp_path: Path) -> None:
    state_path = tmp_path / "provision.json"
    orchestrator = ProvisioningOrchestrator(state_path)
    malformed_host = replace(valid_host(), hyperv_enabled="false")

    with pytest.raises(ValueError, match="hyperv_enabled"):
        orchestrator.reconcile(context(host=malformed_host))

    assert not state_path.exists()


def test_reconcile_uses_expected_state_cas_for_durable_advances() -> None:
    source = inspect.getsource(ProvisioningOrchestrator.reconcile)
    assert "self.store.transition(" not in source
    assert "self._advance(" in source
