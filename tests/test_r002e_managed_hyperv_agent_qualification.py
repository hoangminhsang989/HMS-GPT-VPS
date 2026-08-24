from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hms_gpt_vps.agent_device_credential_store import GUEST_PROTECTION_SCOPE
from hms_gpt_vps.agent_health_contract import (
    AgentHealthDocument,
    DEFAULT_REQUIRED_CAPABILITIES,
)
from hms_gpt_vps.agent_package import (
    build_agent_package_manifest,
    write_agent_package_manifest,
)
from hms_gpt_vps.agent_package_manifest_artifact import canonical_agent_package_manifest_sha256
from hms_gpt_vps.agent_transport_protocol import AgentDeviceCredential
from hms_gpt_vps.managed_hyperv_agent_qualification import (
    MANAGED_HYPERV_AGENT_QUALIFICATION_NAME,
    MANAGED_HYPERV_AGENT_QUALIFICATION_SCHEMA_VERSION,
    ManagedHyperVAgentQualificationError,
    ManagedHyperVAgentQualificationProof,
    qualify_managed_hyperv_agent,
    write_managed_hyperv_agent_qualification_proof,
)
from hms_gpt_vps import managed_hyperv_agent_qualification as qualification_module
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore
from hms_gpt_vps.provisioning import (
    ProvisionContext,
    ProvisionObservation,
    ProvisioningOrchestrator,
    TransitionResult,
)
from hms_gpt_vps.windows_provisioner import HyperVHostState, WindowsVMConfig


VM_ID = "11111111-2222-3333-4444-555555555555"
OTHER_VM_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
DEVICE_ID = "device-01"


def device_credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id="hms-01",
        device_id=DEVICE_ID,
        secret=b"d" * 32,
    )


@pytest.fixture(autouse=True)
def exact_enrollment_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    def probe(_vm_name, _bootstrap, config, expected):  # type: ignore[no-untyped-def]
        assert config.instance_id == "hms-01"
        assert config.guest_state_path == r"C:\ProgramData\HMS-GPT-VPS\State"
        assert config.service_name == "HMSAgent"
        assert expected == device_credential()
        return {
            "enrollment_ready": True,
            "credential_exists": True,
            "instance_id": "hms-01",
            "device_id": DEVICE_ID,
            "protection_scope": GUEST_PROTECTION_SCOPE,
            "credential_path": r"C:\ProgramData\HMS-GPT-VPS\State\agent-device-credential.dpapi",
        }

    monkeypatch.setattr(qualification_module, "probe_agent_device_enrollment", probe)


def make_package(tmp_path: Path):  # type: ignore[no-untyped-def]
    root = tmp_path / "hms-agent"
    root.mkdir()
    (root / "hms-agent.exe").write_bytes(b"entrypoint")
    internal = root / "_internal"
    internal.mkdir()
    (internal / "runtime.dll").write_bytes(b"runtime")
    manifest = build_agent_package_manifest(root, version="0.1.0")
    manifest_path = tmp_path / "hms-agent.manifest.json"
    write_agent_package_manifest(manifest_path, manifest)
    return root, manifest_path, manifest


def make_context() -> ProvisionContext:
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


def health_document() -> AgentHealthDocument:
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
        boot_id="managed-guest-boot-id",
    )


def service_evidence(manifest) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {
        "service_ready": True,
        "local_service_account": True,
        "service_sid_unrestricted": True,
        "package_manifest_sha256_ok": True,
        "package_manifest_sha256": canonical_agent_package_manifest_sha256(manifest),
        "package_tree_ok": True,
        "package_file_count": manifest.file_count,
        "package_total_size": manifest.total_size,
        "binary_sha256": manifest.sha256,
        "runtime_config_sha256_ok": True,
    }


class FakeAgentRuntime:
    def __init__(
        self,
        package_root: Path,
        manifest_path: Path,
        manifest,
        *,
        vm_ids: list[str] | None = None,
        evidence: dict[str, object] | None = None,
        healthy: bool = True,
    ) -> None:  # type: ignore[no-untyped-def]
        self.config = SimpleNamespace(
            instance_id="hms-01",
            vm_name="HMS-GPT-VPS-01",
            package_source_root=package_root,
            package_manifest_path=manifest_path,
            service=SimpleNamespace(
                state_path=r"C:\ProgramData\HMS-GPT-VPS\State",
                service_name="HMSAgent",
            ),
        )
        self._vm_ids = list(vm_ids or [VM_ID])
        self._last_vm_id = self._vm_ids[-1]
        self._manifest = manifest
        self._evidence = evidence or service_evidence(manifest)
        self._healthy = healthy

    def _assert_vm_identity(self) -> str:
        if self._vm_ids:
            self._last_vm_id = self._vm_ids.pop(0)
        return self._last_vm_id

    def observe(self, _credential):  # type: ignore[no-untyped-def]
        health = health_document() if self._healthy else None
        post = SimpleNamespace(
            service_ready=True,
            agent_healthy=self._healthy,
            health=health,
            service_evidence=self._evidence,
        )
        return (
            ProvisionObservation(
                agent_package_ready=True,
                agent_service_ready=True,
                agent_healthy=self._healthy,
            ),
            post,
        )


class FakeReconcileRuntime:
    def __init__(
        self,
        orchestrator: ProvisioningOrchestrator,
        agent_runtime: FakeAgentRuntime,
        *,
        advance_on_call: bool = True,
    ) -> None:
        self.orchestrator = orchestrator
        self.agent_runtime = agent_runtime
        self.advance_on_call = advance_on_call
        self.calls = 0

    def reconcile_once(self, _context, _credential):  # type: ignore[no-untyped-def]
        self.calls += 1
        record = self.orchestrator.store.load()
        assert record is not None
        if self.advance_on_call:
            record = self.orchestrator.store.transition(
                instance_id="hms-01",
                state=ProvisionState.AGENT_HEALTHY,
                reason="qualification-test-health-proof",
            )
        return TransitionResult(
            record=record,
            action="AGENT_APPLICATION_HEALTH_VERIFIED",
        )


def orchestrator_at(tmp_path: Path, state: ProvisionState) -> ProvisioningOrchestrator:
    path = tmp_path / "provision.json"
    ProvisionStateStore(path).transition(instance_id="hms-01", state=state)
    return ProvisioningOrchestrator(path)


def test_final_allowed_reconcile_step_may_reach_agent_healthy(tmp_path: Path) -> None:
    package_root, manifest_path, manifest = make_package(tmp_path)
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_SERVICE_READY)
    agent = FakeAgentRuntime(package_root, manifest_path, manifest)
    runtime = FakeReconcileRuntime(orchestrator, agent)

    proof = qualify_managed_hyperv_agent(
        runtime,  # type: ignore[arg-type]
        make_context(),
        credential(),
        device_credential(),
        max_reconcile_steps=1,
    )

    assert runtime.calls == 1
    assert proof.starting_state == ProvisionState.AGENT_SERVICE_READY.value
    assert proof.final_state == ProvisionState.AGENT_HEALTHY.value
    assert proof.actions == ("AGENT_APPLICATION_HEALTH_VERIFIED",)
    assert proof.vm_id == VM_ID
    assert proof.device_id == DEVICE_ID
    assert proof.device_enrollment_ready is True
    assert proof.device_protection_scope == GUEST_PROTECTION_SCOPE
    assert proof.package_manifest_sha256 == canonical_agent_package_manifest_sha256(manifest)
    assert proof.hyperv_guest_proven is True
    assert proof.full_bridge_command_flow_proven is False
    assert proof.bootstrap_retired is False
    assert proof.pairing_ready is False


def test_missing_provisioning_checkpoint_fails_before_vm_proof(tmp_path: Path) -> None:
    package_root, manifest_path, manifest = make_package(tmp_path)
    orchestrator = ProvisioningOrchestrator(tmp_path / "missing-provision.json")
    agent = FakeAgentRuntime(package_root, manifest_path, manifest)
    runtime = FakeReconcileRuntime(orchestrator, agent)

    with pytest.raises(ManagedHyperVAgentQualificationError, match="existing provisioning"):
        qualify_managed_hyperv_agent(
            runtime,  # type: ignore[arg-type]
            make_context(),
            credential(),
            device_credential(),
        )


def test_vm_id_change_during_qualification_fails_closed(tmp_path: Path) -> None:
    package_root, manifest_path, manifest = make_package(tmp_path)
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_SERVICE_READY)
    agent = FakeAgentRuntime(
        package_root,
        manifest_path,
        manifest,
        vm_ids=[VM_ID, OTHER_VM_ID],
    )
    runtime = FakeReconcileRuntime(orchestrator, agent)

    with pytest.raises(ManagedHyperVAgentQualificationError, match="VMId changed"):
        qualify_managed_hyperv_agent(
            runtime,  # type: ignore[arg-type]
            make_context(),
            credential(),
            device_credential(),
            max_reconcile_steps=1,
        )


def test_host_manifest_change_during_reconcile_fails_closed(tmp_path: Path) -> None:
    package_root, manifest_path, manifest = make_package(tmp_path)
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_SERVICE_READY)
    agent = FakeAgentRuntime(package_root, manifest_path, manifest)
    runtime = FakeReconcileRuntime(orchestrator, agent)
    original = runtime.reconcile_once

    def mutate_manifest(context, bootstrap):  # type: ignore[no-untyped-def]
        result = original(context, bootstrap)
        manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
        return result

    runtime.reconcile_once = mutate_manifest  # type: ignore[method-assign]
    with pytest.raises(ManagedHyperVAgentQualificationError, match="manifest changed"):
        qualify_managed_hyperv_agent(
            runtime,  # type: ignore[arg-type]
            make_context(),
            credential(),
            device_credential(),
            max_reconcile_steps=1,
        )


def test_final_package_evidence_must_match_pinned_host_manifest(tmp_path: Path) -> None:
    package_root, manifest_path, manifest = make_package(tmp_path)
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_HEALTHY)
    evidence = service_evidence(manifest)
    evidence["package_file_count"] = manifest.file_count + 1
    agent = FakeAgentRuntime(package_root, manifest_path, manifest, evidence=evidence)
    runtime = FakeReconcileRuntime(orchestrator, agent)

    with pytest.raises(ManagedHyperVAgentQualificationError, match="file-count"):
        qualify_managed_hyperv_agent(
            runtime,  # type: ignore[arg-type]
            make_context(),
            credential(),
            device_credential(),
        )


def test_guest_manifest_sha_must_match_pinned_host_manifest(tmp_path: Path) -> None:
    package_root, manifest_path, manifest = make_package(tmp_path)
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_HEALTHY)
    evidence = service_evidence(manifest)
    evidence["package_manifest_sha256"] = "0" * 64
    agent = FakeAgentRuntime(package_root, manifest_path, manifest, evidence=evidence)
    runtime = FakeReconcileRuntime(orchestrator, agent)

    with pytest.raises(ManagedHyperVAgentQualificationError, match="guest manifest identity"):
        qualify_managed_hyperv_agent(
            runtime,  # type: ignore[arg-type]
            make_context(),
            credential(),
            device_credential(),
        )


def test_final_application_health_is_mandatory(tmp_path: Path) -> None:
    package_root, manifest_path, manifest = make_package(tmp_path)
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_HEALTHY)
    agent = FakeAgentRuntime(package_root, manifest_path, manifest, healthy=False)
    runtime = FakeReconcileRuntime(orchestrator, agent)

    with pytest.raises(ManagedHyperVAgentQualificationError, match="final Agent observation"):
        qualify_managed_hyperv_agent(
            runtime,  # type: ignore[arg-type]
            make_context(),
            credential(),
            device_credential(),
        )


def test_wrong_enrollment_identity_blocks_hyperv_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root, manifest_path, manifest = make_package(tmp_path)
    orchestrator = orchestrator_at(tmp_path, ProvisionState.AGENT_HEALTHY)
    agent = FakeAgentRuntime(package_root, manifest_path, manifest)
    runtime = FakeReconcileRuntime(orchestrator, agent)
    monkeypatch.setattr(
        qualification_module,
        "probe_agent_device_enrollment",
        lambda *_args, **_kwargs: {
            "enrollment_ready": True,
            "instance_id": "hms-01",
            "device_id": "wrong-device",
            "protection_scope": GUEST_PROTECTION_SCOPE,
        },
    )

    with pytest.raises(ManagedHyperVAgentQualificationError, match="differs from Bridge"):
        qualify_managed_hyperv_agent(
            runtime,  # type: ignore[arg-type]
            make_context(),
            credential(),
            device_credential(),
        )


def valid_proof() -> ManagedHyperVAgentQualificationProof:
    return ManagedHyperVAgentQualificationProof(
        schema_version=MANAGED_HYPERV_AGENT_QUALIFICATION_SCHEMA_VERSION,
        qualification=MANAGED_HYPERV_AGENT_QUALIFICATION_NAME,
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        vm_id=VM_ID,
        device_id=DEVICE_ID,
        device_enrollment_ready=True,
        device_protection_scope=GUEST_PROTECTION_SCOPE,
        starting_state=ProvisionState.AGENT_SERVICE_READY.value,
        final_state=ProvisionState.AGENT_HEALTHY.value,
        actions=("AGENT_APPLICATION_HEALTH_VERIFIED",),
        package_schema_version=2,
        package_version="0.1.0",
        package_file_count=2,
        package_total_size=20,
        package_entrypoint_sha256="a" * 64,
        package_manifest_sha256="b" * 64,
        package_tree_ok=True,
        package_manifest_sha256_ok=True,
        local_service_account=True,
        service_sid_unrestricted=True,
        runtime_config_sha256_ok=True,
        service_ready=True,
        health_status="ok",
        health_agent_version="0.1.0",
        health_service_identity=r"NT SERVICE\HMSAgent",
        health_listener_scope="loopback-only",
        health_privilege="non-admin",
        health_boot_id="boot-proof",
        health_capabilities=tuple(sorted(DEFAULT_REQUIRED_CAPABILITIES)),
        hyperv_guest_proven=True,
        full_bridge_command_flow_proven=False,
        bootstrap_retired=False,
        pairing_ready=False,
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("full_bridge_command_flow_proven", True, "must not claim full Bridge"),
        ("bootstrap_retired", True, "must not claim bootstrap retirement"),
        ("pairing_ready", True, "must not claim pairing readiness"),
        ("device_enrollment_ready", False, "device enrollment is incomplete"),
    ],
)
def test_r002e_proof_refuses_future_stage_or_enrollment_overclaims(
    field: str,
    value: bool,
    message: str,
) -> None:
    proof = replace(valid_proof(), **{field: value})
    with pytest.raises(ValueError, match=message):
        proof.validate()


def test_written_proof_is_non_secret_and_retains_explicit_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "managed-hyperv-proof.json"
    proof = valid_proof()
    write_managed_hyperv_agent_qualification_proof(path, proof)

    raw = path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    lowered_keys = {str(key).casefold() for key in payload}
    assert not {
        "password",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "pairing_token",
    }.intersection(lowered_keys)
    assert payload["device_id"] == DEVICE_ID
    assert payload["device_enrollment_ready"] is True
    assert payload["device_protection_scope"] == GUEST_PROTECTION_SCOPE
    assert payload["package_manifest_sha256"] == "b" * 64
    assert payload["hyperv_guest_proven"] is True
    assert payload["full_bridge_command_flow_proven"] is False
    assert payload["bootstrap_retired"] is False
    assert payload["pairing_ready"] is False
