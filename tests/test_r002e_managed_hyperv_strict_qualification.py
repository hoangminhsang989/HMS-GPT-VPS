from __future__ import annotations

from types import SimpleNamespace

import pytest

from hms_gpt_vps.agent_device_credential_store import GUEST_PROTECTION_SCOPE
from hms_gpt_vps.agent_health_contract import (
    DEFAULT_REQUIRED_CAPABILITIES,
    AgentHealthDocument,
)
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps import managed_hyperv_agent_strict_qualification as strict_module
from hms_gpt_vps.managed_hyperv_agent_strict_qualification import (
    STRICT_MANAGED_HYPERV_PUBLICATION_SCHEMA_VERSION,
    StrictManagedHyperVAgentQualificationError,
    qualify_managed_hyperv_agent_strict,
    validate_strict_managed_hyperv_proof_payload,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps.provisioning import ProvisionObservation


VM_ID = "11111111-2222-3333-4444-555555555555"
OTHER_VM_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
INSTANCE_ID = "hms-01"
DEVICE_ID = "device-01"


class FakeBaseProof:
    instance_id = INSTANCE_ID
    device_id = DEVICE_ID
    vm_id = VM_ID
    hyperv_guest_proven = True
    health_boot_id = "boot-01"
    health_agent_version = "0.1.0"
    package_file_count = 2
    package_total_size = 20
    package_entrypoint_sha256 = "a" * 64
    package_manifest_sha256 = "b" * 64

    def validate(self) -> None:
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "qualification": "managed_hyperv_guest_agent",
            "instance_id": self.instance_id,
            "device_id": self.device_id,
            "hyperv_guest_proven": True,
            "full_bridge_command_flow_proven": False,
            "bootstrap_retired": False,
            "pairing_ready": False,
            "health_listener_scope": "loopback-only",
            "health_boot_id": self.health_boot_id,
            "health_agent_version": self.health_agent_version,
            "package_file_count": self.package_file_count,
            "package_total_size": self.package_total_size,
            "package_entrypoint_sha256": self.package_entrypoint_sha256,
            "package_manifest_sha256": self.package_manifest_sha256,
        }


def health_document(*, boot_id: str = "boot-01") -> AgentHealthDocument:
    return AgentHealthDocument(
        schema_version=1,
        status="ok",
        instance_id=INSTANCE_ID,
        agent_version="0.1.0",
        workspace_root=r"C:\HMS-Workspace",
        capabilities=tuple(sorted(DEFAULT_REQUIRED_CAPABILITIES)),
        service_identity=r"NT SERVICE\HMSAgent",
        listener_scope="loopback-only",
        privilege="non-admin",
        boot_id=boot_id,
    )


def service_evidence(**overrides: object) -> dict[str, object]:
    evidence: dict[str, object] = {
        "package_file_count": 2,
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


def runtime(
    vm_ids: list[str] | None = None,
    *,
    boot_id: str = "boot-01",
    evidence: dict[str, object] | None = None,
):  # type: ignore[no-untyped-def]
    observed = list(vm_ids or [VM_ID, VM_ID, VM_ID, VM_ID])
    last = observed[-1]

    def assert_vm_identity() -> str:
        nonlocal last
        if observed:
            last = observed.pop(0)
        return last

    def observe(_credential):  # type: ignore[no-untyped-def]
        health = health_document(boot_id=boot_id)
        post = SimpleNamespace(
            service_ready=True,
            agent_healthy=True,
            health=health,
            service_evidence=evidence or service_evidence(),
        )
        return (
            ProvisionObservation(
                agent_package_ready=True,
                agent_service_ready=True,
                agent_healthy=True,
            ),
            post,
        )

    agent_runtime = SimpleNamespace(
        config=SimpleNamespace(
            vm_name="HMS-GPT-VPS-01",
            service=AgentServiceConfig(),
            runtime=SimpleNamespace(health_port=8765),
        ),
        _assert_vm_identity=assert_vm_identity,
        observe=observe,
    )
    return SimpleNamespace(agent_runtime=agent_runtime)


def credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential("hmsbootstrap", "temporary-secret")


def expected_device():  # type: ignore[no-untyped-def]
    return SimpleNamespace(instance_id=INSTANCE_ID, device_id=DEVICE_ID)


def valid_strict_payload() -> dict[str, object]:
    return {
        "strict_publication_schema_version": (
            STRICT_MANAGED_HYPERV_PUBLICATION_SCHEMA_VERSION
        ),
        "hyperv_guest_proven": True,
        "os_listener_proven": True,
        "device_enrollment_reproven_at_publication": True,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "health_listener_scope": "loopback-only",
        "health_listener_process_id": 4321,
        "health_listener_count": 1,
        "health_listener_addresses": ["127.0.0.1"],
        "health_listener_port": 8765,
    }


def install_base_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        strict_module,
        "qualify_managed_hyperv_agent",
        lambda *_args, **_kwargs: FakeBaseProof(),
    )
    monkeypatch.setattr(
        strict_module,
        "probe_agent_device_enrollment_by_id",
        lambda *_args, **_kwargs: {
            "enrollment_ready": True,
            "instance_id": INSTANCE_ID,
            "device_id": DEVICE_ID,
            "protection_scope": GUEST_PROTECTION_SCOPE,
        },
    )


def listener(process_id: int = 4321) -> dict[str, object]:
    return {
        "os_listener_proven": True,
        "service_name": "HMSAgent",
        "process_id": process_id,
        "health_port": 8765,
        "listener_count": 1,
        "local_addresses": ["127.0.0.1"],
        "vm_id": VM_ID,
    }


def qualify(runtime_value):  # type: ignore[no-untyped-def]
    return qualify_managed_hyperv_agent_strict(
        runtime_value,
        SimpleNamespace(),  # type: ignore[arg-type]
        credential(),
        expected_device(),  # type: ignore[arg-type]
    )


def test_strict_qualification_brackets_fresh_health_and_reproves_enrollment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    calls: list[tuple[str, str, int]] = []

    def probe(vm_id, vm_name, _credential, service, health_port):  # type: ignore[no-untyped-def]
        calls.append((vm_id, vm_name, health_port))
        assert service.service_name == "HMSAgent"
        return listener()

    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        probe,
    )

    payload = qualify(runtime())

    assert calls == [(VM_ID, "HMS-GPT-VPS-01", 8765)] * 2
    assert payload["strict_publication_schema_version"] == 1
    assert payload["hyperv_guest_proven"] is True
    assert payload["os_listener_proven"] is True
    assert payload["device_enrollment_reproven_at_publication"] is True
    assert payload["health_listener_process_id"] == 4321
    assert payload["health_listener_count"] == 1
    assert payload["health_listener_addresses"] == ["127.0.0.1"]
    assert payload["health_listener_port"] == 8765


def test_strict_qualification_reproves_vm_id_before_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)

    def forbidden(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("listener probe must not run after pre-proof VMId change")

    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        forbidden,
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="before strict"):
        qualify(runtime([OTHER_VM_ID]))


def test_strict_qualification_reproves_vm_id_during_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: listener(),
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="health observation"):
        qualify(runtime([VM_ID, OTHER_VM_ID]))


def test_strict_qualification_reproves_vm_id_after_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: listener(),
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="during strict listener"):
        qualify(runtime([VM_ID, VM_ID, OTHER_VM_ID]))


def test_strict_qualification_reproves_vm_id_after_enrollment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: listener(),
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="enrollment proof"):
        qualify(runtime([VM_ID, VM_ID, VM_ID, OTHER_VM_ID]))


def test_strict_qualification_rejects_service_pid_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    probes = iter((listener(4321), listener(9876)))
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: next(probes),
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="service process changed"):
        qualify(runtime())


def test_strict_qualification_rejects_service_boot_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: listener(),
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="service incarnation"):
        qualify(runtime(boot_id="boot-02"))


def test_strict_qualification_rejects_package_evidence_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: listener(),
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="package_file_count"):
        qualify(runtime(evidence=service_evidence(package_file_count=3)))


def test_strict_qualification_rejects_publication_enrollment_identity_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: listener(),
    )
    monkeypatch.setattr(
        strict_module,
        "probe_agent_device_enrollment_by_id",
        lambda *_args, **_kwargs: {
            "enrollment_ready": True,
            "instance_id": INSTANCE_ID,
            "device_id": "wrong-device",
            "protection_scope": GUEST_PROTECTION_SCOPE,
        },
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="identity changed"):
        qualify(runtime())


def test_strict_qualification_refuses_incomplete_listener_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: {
            "os_listener_proven": False,
            "vm_id": VM_ID,
        },
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="incomplete"):
        qualify(runtime())


def test_strict_qualification_refuses_listener_vm_id_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_base_mock(monkeypatch)
    monkeypatch.setattr(
        strict_module,
        "probe_managed_agent_health_listener_by_id",
        lambda *_args, **_kwargs: {
            "os_listener_proven": True,
            "vm_id": OTHER_VM_ID,
        },
    )

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="wrong VMId"):
        qualify(runtime())


@pytest.mark.parametrize(
    ("key", "value", "match"),
    [
        ("strict_publication_schema_version", 2, "schema mismatch"),
        ("hyperv_guest_proven", False, "guest path"),
        ("os_listener_proven", False, "OS listener"),
        ("device_enrollment_reproven_at_publication", False, "device enrollment"),
        ("full_bridge_command_flow_proven", True, "forbidden"),
        ("bootstrap_retired", True, "forbidden"),
        ("pairing_ready", True, "forbidden"),
        ("health_listener_scope", "all-interfaces", "loopback-only"),
        ("health_listener_process_id", True, "process id"),
        ("health_listener_process_id", 0, "process id"),
        ("health_listener_count", True, "listener count"),
        ("health_listener_count", 2, "listener count"),
        ("health_listener_addresses", ["0.0.0.0"], "exclusive IPv4 loopback"),
        ("health_listener_port", True, "listener port"),
        ("health_listener_port", 70000, "listener port"),
    ],
)
def test_strict_payload_validator_rejects_malformed_or_overclaiming_evidence(
    key: str,
    value: object,
    match: str,
) -> None:
    payload = valid_strict_payload()
    payload[key] = value

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match=match):
        validate_strict_managed_hyperv_proof_payload(
            payload,
            expected_health_port=8765,
        )


def test_strict_payload_validator_rejects_runtime_port_mismatch() -> None:
    payload = valid_strict_payload()

    with pytest.raises(StrictManagedHyperVAgentQualificationError, match="runtime config"):
        validate_strict_managed_hyperv_proof_payload(
            payload,
            expected_health_port=18765,
        )
