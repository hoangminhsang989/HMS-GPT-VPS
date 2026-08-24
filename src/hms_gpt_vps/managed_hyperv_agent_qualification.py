from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .agent_device_credential_store import GUEST_PROTECTION_SCOPE
from .agent_device_enrollment import AgentDeviceEnrollmentConfig
from .agent_health_contract import AgentHealthDocument
from .agent_package import load_agent_package_manifest, verify_agent_package
from .agent_package_manifest_artifact import (
    canonical_agent_package_manifest_bytes,
    canonical_agent_package_manifest_sha256,
)
from .agent_transport_protocol import AgentDeviceCredential
from .managed_agent_reconcile_runtime import ManagedAgentReconcileRuntime
from .managed_vm_id_operations import probe_agent_device_enrollment_by_id
from .powershell_direct import PowerShellDirectCredential
from .provision_state import ProvisionState
from .provisioning import ProvisionContext


MANAGED_HYPERV_AGENT_QUALIFICATION_SCHEMA_VERSION = 1
MANAGED_HYPERV_AGENT_QUALIFICATION_NAME = "managed_hyperv_guest_agent"
_DEFAULT_MAX_RECONCILE_STEPS = 8


class ManagedHyperVAgentQualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManagedHyperVAgentQualificationProof:
    schema_version: int
    qualification: str
    instance_id: str
    vm_name: str
    vm_id: str
    device_id: str
    device_enrollment_ready: bool
    device_protection_scope: str
    starting_state: str
    final_state: str
    actions: tuple[str, ...]
    package_schema_version: int
    package_version: str
    package_file_count: int
    package_total_size: int
    package_entrypoint_sha256: str
    package_manifest_sha256: str
    package_tree_ok: bool
    package_manifest_sha256_ok: bool
    local_service_account: bool
    service_sid_unrestricted: bool
    runtime_config_sha256_ok: bool
    service_ready: bool
    health_status: str
    health_agent_version: str
    health_service_identity: str
    health_listener_scope: str
    health_privilege: str
    health_boot_id: str
    health_capabilities: tuple[str, ...]
    hyperv_guest_proven: bool
    full_bridge_command_flow_proven: bool
    bootstrap_retired: bool
    pairing_ready: bool

    def validate(self) -> None:
        if self.schema_version != MANAGED_HYPERV_AGENT_QUALIFICATION_SCHEMA_VERSION:
            raise ValueError("managed Hyper-V qualification proof schema mismatch")
        if self.qualification != MANAGED_HYPERV_AGENT_QUALIFICATION_NAME:
            raise ValueError("managed Hyper-V qualification proof type mismatch")
        if not self.instance_id.strip() or not self.vm_name.strip() or not self.vm_id.strip():
            raise ValueError("managed Hyper-V qualification identity fields are required")
        if not self.device_id.strip() or not self.device_enrollment_ready:
            raise ValueError("managed Hyper-V qualification device enrollment is incomplete")
        if self.device_protection_scope != GUEST_PROTECTION_SCOPE:
            raise ValueError("managed Hyper-V qualification device credential is not LocalMachine")
        if self.final_state != ProvisionState.AGENT_HEALTHY.value:
            raise ValueError("managed Hyper-V qualification must finish at AGENT_HEALTHY")
        if not self.hyperv_guest_proven:
            raise ValueError("managed Hyper-V qualification must explicitly prove the guest path")
        if self.full_bridge_command_flow_proven:
            raise ValueError("R002E proof must not claim full Bridge command flow")
        if self.bootstrap_retired:
            raise ValueError("R002E proof must not claim bootstrap retirement")
        if self.pairing_ready:
            raise ValueError("R002E proof must not claim pairing readiness")
        if not all(
            (
                self.package_tree_ok,
                self.package_manifest_sha256_ok,
                self.local_service_account,
                self.service_sid_unrestricted,
                self.runtime_config_sha256_ok,
                self.service_ready,
            )
        ):
            raise ValueError("managed Hyper-V SCM/package readiness proof is incomplete")
        if self.health_status != "ok":
            raise ValueError("managed Hyper-V Agent application health is not ok")
        if self.health_service_identity.casefold() != r"NT SERVICE\HMSAgent".casefold():
            raise ValueError("managed Hyper-V health service identity is not HMSAgent")
        if self.health_listener_scope != "loopback-only":
            raise ValueError("managed Hyper-V Agent health listener is not loopback-only")
        if self.health_privilege != "non-admin":
            raise ValueError("managed Hyper-V Agent health privilege is not non-admin")
        if self.health_agent_version != self.package_version:
            raise ValueError("managed Hyper-V health/package version mismatch")
        if self.package_file_count <= 0 or self.package_total_size <= 0:
            raise ValueError("managed Hyper-V package proof is empty")
        if len(self.package_entrypoint_sha256) != 64:
            raise ValueError("managed Hyper-V package entrypoint SHA-256 is invalid")
        if len(self.package_manifest_sha256) != 64:
            raise ValueError("managed Hyper-V package manifest SHA-256 is invalid")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        payload = asdict(self)
        payload["actions"] = list(self.actions)
        payload["health_capabilities"] = list(self.health_capabilities)
        return payload


def _require_bool(evidence: dict[str, object], key: str) -> bool:
    value = evidence.get(key)
    if value is not True:
        raise ManagedHyperVAgentQualificationError(
            f"managed Hyper-V readiness evidence is not proven: {key}"
        )
    return True


def _require_int(evidence: dict[str, object], key: str) -> int:
    value = evidence.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ManagedHyperVAgentQualificationError(
            f"managed Hyper-V readiness evidence is not an integer: {key}"
        )
    return value


def _final_health(post: Any) -> AgentHealthDocument:
    if post is None or not bool(getattr(post, "service_ready", False)):
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V final service readiness was not proven"
        )
    if not bool(getattr(post, "agent_healthy", False)):
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V final application health was not proven"
        )
    health = getattr(post, "health", None)
    if not isinstance(health, AgentHealthDocument):
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V final health document is missing"
        )
    return health


def _prove_exact_device_enrollment(
    vm_id: str,
    agent_runtime: Any,
    credential: PowerShellDirectCredential,
    expected_device_credential: AgentDeviceCredential,
) -> dict[str, object]:
    enrollment_config = AgentDeviceEnrollmentConfig(
        instance_id=expected_device_credential.instance_id,
        guest_state_path=agent_runtime.config.service.state_path,
        service_name=agent_runtime.config.service.service_name,
    )
    evidence = probe_agent_device_enrollment_by_id(
        vm_id,
        agent_runtime.config.vm_name,
        credential,
        enrollment_config,
        expected_device_credential,
    )
    if not bool(evidence.get("enrollment_ready", False)):
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V device enrollment was not independently proven"
        )
    if evidence.get("instance_id") != expected_device_credential.instance_id:
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V device enrollment instance differs from Bridge authority"
        )
    if evidence.get("device_id") != expected_device_credential.device_id:
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V device enrollment identity differs from Bridge authority"
        )
    if evidence.get("protection_scope") != GUEST_PROTECTION_SCOPE:
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V device enrollment is not LocalMachine-DPAPI protected"
        )
    return evidence


def qualify_managed_hyperv_agent(
    reconcile_runtime: ManagedAgentReconcileRuntime,
    context: ProvisionContext,
    credential: PowerShellDirectCredential,
    expected_device_credential: AgentDeviceCredential,
    *,
    max_reconcile_steps: int = _DEFAULT_MAX_RECONCILE_STEPS,
) -> ManagedHyperVAgentQualificationProof:
    """Prove the late Agent path inside one already-managed Hyper-V Windows guest.

    This coordinator never creates/deletes a VM and never retires bootstrap
    credentials. It pins the exact host package manifest, re-proves stable
    Hyper-V identity and the Bridge-bound LocalMachine-DPAPI device credential,
    exercises the production late reconcile runtime until AGENT_HEALTHY, then
    independently re-verifies package, SCM and strict application health. Every
    qualification guest call after stable identity is proven is bound to VMId.
    """

    credential.validate()
    expected_device_credential.validate()
    if max_reconcile_steps < 1 or max_reconcile_steps > 32:
        raise ValueError("max_reconcile_steps must be between 1 and 32")

    agent_runtime = reconcile_runtime.agent_runtime
    if context.instance_id != agent_runtime.config.instance_id:
        raise ManagedHyperVAgentQualificationError(
            "qualification context belongs to another managed instance"
        )
    if expected_device_credential.instance_id != context.instance_id:
        raise ManagedHyperVAgentQualificationError(
            "qualification device credential belongs to another managed instance"
        )

    manifest = load_agent_package_manifest(agent_runtime.config.package_manifest_path)
    pinned_manifest_bytes = canonical_agent_package_manifest_bytes(manifest)
    pinned_manifest_sha256 = canonical_agent_package_manifest_sha256(manifest)
    if agent_runtime.config.package_manifest_path.read_bytes() != pinned_manifest_bytes:
        raise ManagedHyperVAgentQualificationError(
            "qualification package manifest is not canonical"
        )
    verify_agent_package(agent_runtime.config.package_source_root, manifest)

    starting_record = reconcile_runtime.orchestrator.store.load()
    if starting_record is None:
        raise ManagedHyperVAgentQualificationError(
            "qualification requires an existing provisioning checkpoint"
        )
    if starting_record.instance_id != context.instance_id:
        raise ManagedHyperVAgentQualificationError(
            "qualification provisioning checkpoint belongs to another instance"
        )
    if starting_record.state not in {
        ProvisionState.AGENT_INSTALLING,
        ProvisionState.AGENT_SERVICE_READY,
        ProvisionState.AGENT_HEALTHY,
    }:
        raise ManagedHyperVAgentQualificationError(
            "qualification must start at the managed late-Agent checkpoint"
        )

    starting_vm_id = agent_runtime._assert_vm_identity()
    _prove_exact_device_enrollment(
        starting_vm_id,
        agent_runtime,
        credential,
        expected_device_credential,
    )

    actions: list[str] = []
    for _ in range(max_reconcile_steps):
        record = reconcile_runtime.orchestrator.store.load()
        if record is None:
            raise ManagedHyperVAgentQualificationError(
                "qualification provisioning checkpoint disappeared"
            )
        if record.state is ProvisionState.AGENT_HEALTHY:
            break
        result = reconcile_runtime.reconcile_once(context, credential)
        actions.append(result.action)
        post_step_record = reconcile_runtime.orchestrator.store.load()
        if post_step_record is None:
            raise ManagedHyperVAgentQualificationError(
                "qualification provisioning checkpoint disappeared after reconcile"
            )
        if post_step_record.state is ProvisionState.AGENT_HEALTHY:
            break
    else:
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V Agent qualification exceeded reconcile step bound"
        )

    final_record = reconcile_runtime.orchestrator.store.load()
    if final_record is None or final_record.state is not ProvisionState.AGENT_HEALTHY:
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V Agent qualification did not reach AGENT_HEALTHY"
        )

    ending_vm_id = agent_runtime._assert_vm_identity()
    if ending_vm_id != starting_vm_id:
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V VMId changed during Agent qualification"
        )
    _prove_exact_device_enrollment(
        ending_vm_id,
        agent_runtime,
        credential,
        expected_device_credential,
    )

    # Re-read and re-verify host authority after all mutations. This prevents a
    # same-count/same-size package swap from escaping the pinned manifest proof.
    if agent_runtime.config.package_manifest_path.read_bytes() != pinned_manifest_bytes:
        raise ManagedHyperVAgentQualificationError(
            "qualification package manifest changed during managed guest execution"
        )
    final_host_manifest = load_agent_package_manifest(
        agent_runtime.config.package_manifest_path
    )
    if final_host_manifest != manifest:
        raise ManagedHyperVAgentQualificationError(
            "qualification package manifest identity changed during execution"
        )
    verify_agent_package(agent_runtime.config.package_source_root, manifest)

    final_observation, post = agent_runtime.observe(credential)
    if not (
        final_observation.agent_package_ready
        and final_observation.agent_service_ready
        and final_observation.agent_healthy
    ):
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V final Agent observation is incomplete"
        )
    health = _final_health(post)
    service_evidence = dict(post.service_evidence)

    package_file_count = _require_int(service_evidence, "package_file_count")
    package_total_size = _require_int(service_evidence, "package_total_size")
    if package_file_count != manifest.file_count:
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V package file-count evidence differs from pinned host manifest"
        )
    if package_total_size != manifest.total_size:
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V package size evidence differs from pinned host manifest"
        )
    binary_sha256 = service_evidence.get("binary_sha256")
    if not isinstance(binary_sha256, str) or binary_sha256.lower() != manifest.sha256.lower():
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V package entrypoint evidence differs from pinned host manifest"
        )
    guest_manifest_sha256 = service_evidence.get("package_manifest_sha256")
    if (
        not isinstance(guest_manifest_sha256, str)
        or guest_manifest_sha256.lower() != pinned_manifest_sha256
    ):
        raise ManagedHyperVAgentQualificationError(
            "managed Hyper-V guest manifest identity differs from pinned host manifest"
        )

    proof = ManagedHyperVAgentQualificationProof(
        schema_version=MANAGED_HYPERV_AGENT_QUALIFICATION_SCHEMA_VERSION,
        qualification=MANAGED_HYPERV_AGENT_QUALIFICATION_NAME,
        instance_id=context.instance_id,
        vm_name=agent_runtime.config.vm_name,
        vm_id=starting_vm_id,
        device_id=expected_device_credential.device_id,
        device_enrollment_ready=True,
        device_protection_scope=GUEST_PROTECTION_SCOPE,
        starting_state=starting_record.state.value,
        final_state=final_record.state.value,
        actions=tuple(actions),
        package_schema_version=manifest.schema_version,
        package_version=manifest.version,
        package_file_count=manifest.file_count,
        package_total_size=manifest.total_size,
        package_entrypoint_sha256=manifest.sha256.lower(),
        package_manifest_sha256=pinned_manifest_sha256,
        package_tree_ok=_require_bool(service_evidence, "package_tree_ok"),
        package_manifest_sha256_ok=_require_bool(
            service_evidence, "package_manifest_sha256_ok"
        ),
        local_service_account=_require_bool(service_evidence, "local_service_account"),
        service_sid_unrestricted=_require_bool(
            service_evidence, "service_sid_unrestricted"
        ),
        runtime_config_sha256_ok=_require_bool(
            service_evidence, "runtime_config_sha256_ok"
        ),
        service_ready=_require_bool(service_evidence, "service_ready"),
        health_status=health.status,
        health_agent_version=health.agent_version,
        health_service_identity=health.service_identity,
        health_listener_scope=health.listener_scope,
        health_privilege=health.privilege,
        health_boot_id=health.boot_id,
        health_capabilities=tuple(sorted(health.capabilities)),
        hyperv_guest_proven=True,
        full_bridge_command_flow_proven=False,
        bootstrap_retired=False,
        pairing_ready=False,
    )
    proof.validate()
    return proof


def write_managed_hyperv_agent_qualification_proof(
    path: Path,
    proof: ManagedHyperVAgentQualificationProof,
) -> None:
    """Atomically publish the non-secret qualification proof JSON."""

    proof.validate()
    target = path.expanduser().absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            proof.to_dict(),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )
    temp: Path | None = None
    try:
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=target.parent,
            prefix=target.name + ".",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(payload)
            handle.flush()
            temp = Path(handle.name)
        temp.replace(target)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
