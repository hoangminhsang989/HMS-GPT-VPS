from __future__ import annotations

import pytest

from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps import managed_guest_listener_probe as listener_module
from hms_gpt_vps.managed_guest_listener_probe import (
    ManagedGuestListenerProofError,
    probe_managed_agent_health_listener_by_id,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential


VM_ID = "11111111-2222-3333-4444-555555555555"
VM_NAME = "HMS-GPT-VPS-01"


def credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "temporary-secret")


def test_listener_probe_is_vm_id_bound_and_uses_os_socket_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def run(vm_id, vm_name, _credential, script, *, timeout_seconds):  # type: ignore[no-untyped-def]
        seen.update(
            vm_id=vm_id,
            vm_name=vm_name,
            script=script,
            timeout_seconds=timeout_seconds,
        )
        return {
            "service_name": "HMSAgent",
            "process_id": 4321,
            "health_port": 8765,
            "listener_count": 1,
            "local_addresses": ["127.0.0.1"],
        }

    monkeypatch.setattr(listener_module, "run_vm_powershell_json_by_id", run)
    proof = probe_managed_agent_health_listener_by_id(
        VM_ID,
        VM_NAME,
        credential(),
        AgentServiceConfig(),
        8765,
    )

    assert seen["vm_id"] == VM_ID
    assert seen["vm_name"] == VM_NAME
    script = str(seen["script"])
    assert "Get-CimInstance Win32_Service" in script
    assert "Get-NetTCPConnection -State Listen" in script
    assert "OwningProcess" in script
    assert proof == {
        "os_listener_proven": True,
        "service_name": "HMSAgent",
        "process_id": 4321,
        "health_port": 8765,
        "listener_count": 1,
        "local_addresses": ["127.0.0.1"],
        "vm_id": VM_ID,
    }


@pytest.mark.parametrize(
    ("listener_count", "addresses", "match"),
    [
        (2, ["127.0.0.1", "127.0.0.1"], "exactly one"),
        (True, ["127.0.0.1"], "exactly one"),
        ("1", ["127.0.0.1"], "exactly one"),
        (1, ["0.0.0.0"], "exclusively"),
        (1, ["::"], "exclusively"),
    ],
)
def test_listener_probe_rejects_nonexclusive_socket_evidence(
    monkeypatch: pytest.MonkeyPatch,
    listener_count: object,
    addresses: list[str],
    match: str,
) -> None:
    monkeypatch.setattr(
        listener_module,
        "run_vm_powershell_json_by_id",
        lambda *_args, **_kwargs: {
            "service_name": "HMSAgent",
            "process_id": 4321,
            "health_port": 8765,
            "listener_count": listener_count,
            "local_addresses": addresses,
        },
    )

    with pytest.raises(ManagedGuestListenerProofError, match=match):
        probe_managed_agent_health_listener_by_id(
            VM_ID,
            VM_NAME,
            credential(),
            AgentServiceConfig(),
            8765,
        )


def test_listener_probe_rejects_invalid_service_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        listener_module,
        "run_vm_powershell_json_by_id",
        lambda *_args, **_kwargs: {
            "service_name": "HMSAgent",
            "process_id": 0,
            "health_port": 8765,
            "listener_count": 1,
            "local_addresses": ["127.0.0.1"],
        },
    )

    with pytest.raises(ManagedGuestListenerProofError, match="process id"):
        probe_managed_agent_health_listener_by_id(
            VM_ID,
            VM_NAME,
            credential(),
            AgentServiceConfig(),
            8765,
        )


def test_listener_probe_rejects_boolean_health_port_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        listener_module,
        "run_vm_powershell_json_by_id",
        lambda *_args, **_kwargs: {
            "service_name": "HMSAgent",
            "process_id": 4321,
            "health_port": True,
            "listener_count": 1,
            "local_addresses": ["127.0.0.1"],
        },
    )

    with pytest.raises(ManagedGuestListenerProofError, match="wrong health port"):
        probe_managed_agent_health_listener_by_id(
            VM_ID,
            VM_NAME,
            credential(),
            AgentServiceConfig(),
            8765,
        )
