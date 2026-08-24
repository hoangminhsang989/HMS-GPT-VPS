from __future__ import annotations

from types import SimpleNamespace

import pytest

from hms_gpt_vps.agent_health_contract import (
    DEFAULT_REQUIRED_CAPABILITIES,
    AgentHealthDocument,
)
from hms_gpt_vps.managed_hyperv_agent_strict_qualification import (
    StrictManagedHyperVAgentQualificationError,
    _require_fresh_observation_matches_base,
    _require_listener_matches,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps.provisioning import ProvisionObservation


VM_ID = "11111111-2222-3333-4444-555555555555"


def _health() -> AgentHealthDocument:
    return AgentHealthDocument(
        schema_version=1,
        status="ok",
        instance_id="hms-01",
        agent_version="0.1.0",
        workspace_root=r"C:\HMS-Workspace",
        capabilities=tuple(sorted(DEFAULT_REQUIRED_CAPABILITIES)),
        service_identity=r"NT SERVICE\HMSAgent",
        listener_scope="loopback-only",
        privilege="non-admin",
        boot_id="boot-01",
    )


def _base_proof() -> SimpleNamespace:
    return SimpleNamespace(
        health_boot_id="boot-01",
        health_agent_version="0.1.0",
        package_file_count=1,
        package_total_size=20,
        package_entrypoint_sha256="a" * 64,
        package_manifest_sha256="b" * 64,
    )


def _evidence(**overrides: object) -> dict[str, object]:
    evidence: dict[str, object] = {
        "package_file_count": 1,
        "package_total_size": 20,
        "binary_sha256": "a" * 64,
        "package_manifest_sha256": "b" * 64,
        "package_tree_ok": True,
        "package_manifest_sha256_ok": True,
        "local_service_account": True,
        "service_sid_unrestricted": True,
        "runtime_config_sha256_ok": True,
        "service_ready": True,
    }
    evidence.update(overrides)
    return evidence


def _runtime(service_evidence: dict[str, object]) -> SimpleNamespace:
    post = SimpleNamespace(
        service_ready=True,
        agent_healthy=True,
        health=_health(),
        service_evidence=service_evidence,
    )

    def observe(_credential):  # type: ignore[no-untyped-def]
        return (
            ProvisionObservation(
                agent_package_ready=True,
                agent_service_ready=True,
                agent_healthy=True,
            ),
            post,
        )

    return SimpleNamespace(observe=observe)


def test_fresh_publication_rejects_boolean_true_as_integer_one() -> None:
    with pytest.raises(
        StrictManagedHyperVAgentQualificationError,
        match="package_file_count",
    ):
        _require_fresh_observation_matches_base(
            _runtime(_evidence(package_file_count=True)),
            PowerShellDirectCredential("hmsbootstrap", "temporary-secret"),
            _base_proof(),
        )


def test_fresh_publication_rejects_truthy_non_boolean_observation() -> None:
    post = SimpleNamespace(
        service_ready=True,
        agent_healthy=True,
        health=_health(),
        service_evidence=_evidence(),
    )

    def observe(_credential):  # type: ignore[no-untyped-def]
        return (
            SimpleNamespace(
                agent_package_ready="true",
                agent_service_ready=True,
                agent_healthy=True,
            ),
            post,
        )

    with pytest.raises(
        StrictManagedHyperVAgentQualificationError,
        match="fresh Agent observation is incomplete",
    ):
        _require_fresh_observation_matches_base(
            SimpleNamespace(observe=observe),
            PowerShellDirectCredential("hmsbootstrap", "temporary-secret"),
            _base_proof(),
        )


def test_listener_bracket_rejects_boolean_listener_count() -> None:
    listener: dict[str, object] = {
        "os_listener_proven": True,
        "vm_id": VM_ID,
        "process_id": 4321,
        "health_port": 8765,
        "listener_count": True,
        "local_addresses": ["127.0.0.1"],
    }

    with pytest.raises(
        StrictManagedHyperVAgentQualificationError,
        match="invalid listener count",
    ):
        _require_listener_matches(
            listener,
            expected_vm_id=VM_ID,
            expected_health_port=8765,
        )
