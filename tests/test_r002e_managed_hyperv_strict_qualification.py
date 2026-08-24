from __future__ import annotations

from types import SimpleNamespace

import pytest

from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps import managed_hyperv_agent_strict_qualification as strict_module
from hms_gpt_vps.managed_hyperv_agent_strict_qualification import (
    StrictManagedHyperVAgentQualificationError,
    qualify_managed_hyperv_agent_strict,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential


VM_ID = "11111111-2222-3333-4444-555555555555"


class FakeBaseProof:
    vm_id = VM_ID
    hyperv_guest_proven = True

    def validate(self) -> None:
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "qualification": "managed_hyperv_guest_agent",
            "hyperv_guest_proven": True,
            "full_bridge_command_flow_proven": False,
            "bootstrap_retired": False,
            "pairing_ready": False,
        }


def runtime():  # type: ignore[no-untyped-def]
    agent_runtime = SimpleNamespace(
        config=SimpleNamespace(
            vm_name="HMS-GPT-VPS-01",
            service=AgentServiceConfig(),
            runtime=SimpleNamespace(health_port=8765),
        )
    )
    return SimpleNamespace(agent_runtime=agent_runtime)


def credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "temporary-secret")


def test_strict_qualification_adds_independent_os_listener_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        strict_module,
        "qualify_managed_hyperv_agent",
        lambda *_args, **_kwargs: FakeBaseProof(),
    )

    seen: dict[str, object] = {}

    def listener(vm_id, vm_name, _credential, service, health_port):  # type: ignore[no-untyped-def]
        seen.update(
            vm_id=vm_id,
            vm_name=vm_name,
            service_name=service.service_name,
            health_port=health_port,
        )
        return {
            "os_listener_proven": True,
            "service_name": "HMSAgent",
            "process_id": 4321,
            "health_port": 8765,
            "listener_count": 1,
            "local_addresses": ["127.0.0.1"],
            "vm_id": VM_ID,
        }

    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        listener,
    )

    payload = qualify_managed_hyperv_agent_strict(
        runtime(),
        SimpleNamespace(),  # type: ignore[arg-type]
        credential(),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert seen == {
        "vm_id": VM_ID,
        "vm_name": "HMS-GPT-VPS-01",
        "service_name": "HMSAgent",
        "health_port": 8765,
    }
    assert payload["hyperv_guest_proven"] is True
    assert payload["os_listener_proven"] is True
    assert payload["health_listener_process_id"] == 4321
    assert payload["health_listener_count"] == 1
    assert payload["health_listener_addresses"] == ["127.0.0.1"]
    assert payload["health_listener_port"] == 8765


def test_strict_qualification_refuses_incomplete_listener_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        strict_module,
        "qualify_managed_hyperv_agent",
        lambda *_args, **_kwargs: FakeBaseProof(),
    )
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: {
            "os_listener_proven": False,
            "vm_id": VM_ID,
        },
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="incomplete"):
        qualify_managed_hyperv_agent_strict(
            runtime(),
            SimpleNamespace(),  # type: ignore[arg-type]
            credential(),
            SimpleNamespace(),  # type: ignore[arg-type]
        )


def test_strict_qualification_refuses_listener_vm_id_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        strict_module,
        "qualify_managed_hyperv_agent",
        lambda *_args, **_kwargs: FakeBaseProof(),
    )
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: {
            "os_listener_proven": True,
            "vm_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        },
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="wrong VMId"):
        qualify_managed_hyperv_agent_strict(
            runtime(),
            SimpleNamespace(),  # type: ignore[arg-type]
            credential(),
            SimpleNamespace(),  # type: ignore[arg-type]
        )
