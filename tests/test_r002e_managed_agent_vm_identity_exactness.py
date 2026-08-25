from __future__ import annotations

from types import SimpleNamespace

import pytest

import hms_gpt_vps.managed_agent_provisioning_runtime as runtime_module
from hms_gpt_vps.managed_agent_provisioning_runtime import (
    ManagedAgentProvisioningError,
    ManagedAgentProvisioningRuntime,
)


VM_ID = "11111111-1111-1111-1111-111111111111"
VM_NAME = "HMS-GPT-VPS-01"


def _runtime() -> ManagedAgentProvisioningRuntime:
    runtime = object.__new__(ManagedAgentProvisioningRuntime)
    runtime.config = SimpleNamespace(vm_name=VM_NAME)
    runtime._expected_vm_id = lambda: VM_ID  # type: ignore[method-assign]
    return runtime


def _set_evidence(monkeypatch: pytest.MonkeyPatch, evidence: object) -> None:
    monkeypatch.setattr(
        runtime_module,
        "run_powershell_json",
        lambda *args, **kwargs: evidence,
    )


def test_vm_identity_accepts_only_canonical_string_guid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    _set_evidence(
        monkeypatch,
        {"vm_id": VM_ID, "vm_name": VM_NAME},
    )
    assert runtime._assert_vm_identity() == VM_ID


def test_vm_identity_rejects_numeric_guid_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    _set_evidence(
        monkeypatch,
        {"vm_id": int("1" * 32), "vm_name": VM_NAME},
    )
    with pytest.raises(ManagedAgentProvisioningError, match="observed VMId"):
        runtime._assert_vm_identity()


def test_vm_identity_rejects_noncanonical_guid_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    _set_evidence(
        monkeypatch,
        {"vm_id": VM_ID.upper(), "vm_name": VM_NAME},
    )
    with pytest.raises(ManagedAgentProvisioningError, match="not canonical"):
        runtime._assert_vm_identity()


def test_vm_identity_rejects_schema_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    _set_evidence(
        monkeypatch,
        {"vm_id": VM_ID, "vm_name": VM_NAME, "extra": True},
    )
    with pytest.raises(ManagedAgentProvisioningError, match="schema"):
        runtime._assert_vm_identity()


def test_vm_identity_rejects_non_string_vm_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()
    _set_evidence(
        monkeypatch,
        {"vm_id": VM_ID, "vm_name": 123},
    )
    with pytest.raises(ManagedAgentProvisioningError, match="VM name"):
        runtime._assert_vm_identity()
