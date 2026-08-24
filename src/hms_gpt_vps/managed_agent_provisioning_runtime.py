from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import uuid

from .agent_package import (
    AgentPackageManifest,
    load_agent_package_manifest,
    verify_agent_package,
)
from .agent_package_manifest_artifact import (
    canonical_agent_package_manifest_bytes,
    canonical_agent_package_manifest_sha256,
)
from .agent_package_transfer import (
    AgentPackageTransferPlan,
    transfer_agent_package_to_guest,
)
from .agent_package_transfer_attempt import (
    AgentPackageTransferAttempt,
    AgentPackageTransferAttemptStore,
    AgentPackageTransferPhase,
)
from .agent_package_transfer_recovery import (
    probe_agent_package_ready,
    probe_guest_service_interface_enabled,
    reset_owned_agent_package_staging,
    restore_guest_service_interface_state,
)
from .agent_post_install_observe import (
    AgentPostInstallObservation,
    AgentPostInstallObservationConfig,
    AgentPostInstallObserver,
)
from .agent_service_install import AgentServiceConfig, install_agent_service
from .agent_service_runtime_config import AgentServiceRuntimeConfig
from .instance_registry import InstanceRegistry
from .powershell import ps_literal, run_powershell_json
from .powershell_direct import PowerShellDirectCredential
from .provisioning import ProvisionObservation


class ManagedAgentProvisioningError(RuntimeError):
    pass


def _same_windows_path(left: str, right: str) -> bool:
    return str(PureWindowsPath(left)).casefold() == str(PureWindowsPath(right)).casefold()


def _normalize_vm_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManagedAgentProvisioningError(f"{label} is missing")
    try:
        return str(uuid.UUID(value.strip())).lower()
    except (ValueError, AttributeError) as exc:
        raise ManagedAgentProvisioningError(f"{label} is not a valid GUID") from exc


@dataclass(frozen=True)
class ManagedAgentProvisioningConfig:
    instance_id: str
    vm_name: str
    package_source_root: Path
    package_manifest_path: Path
    registry_path: Path
    service: AgentServiceConfig
    runtime: AgentServiceRuntimeConfig

    def validate(self) -> None:
        if not self.instance_id.strip():
            raise ValueError("instance_id is required")
        if not self.vm_name.strip():
            raise ValueError("vm_name is required")
        self.service.validate()
        self.runtime.validate()
        if self.runtime.instance_id != self.instance_id:
            raise ValueError("runtime config belongs to another managed instance")
        if not _same_windows_path(self.runtime.workspace_root, self.service.workspace_path):
            raise ValueError("runtime workspace_root conflicts with service workspace path")
        if not _same_windows_path(self.runtime.state_root, self.service.state_path):
            raise ValueError("runtime state_root conflicts with service state path")
        if not self.package_source_root.is_dir():
            raise FileNotFoundError(self.package_source_root)
        if not self.package_manifest_path.is_file():
            raise FileNotFoundError(self.package_manifest_path)
        if not self.registry_path.is_file():
            raise FileNotFoundError(self.registry_path)
        if self.registry_path.is_symlink():
            raise ValueError("instance registry path must not be a symbolic link")


class ManagedAgentProvisioningRuntime:
    """Crash-safe host runtime for Agent package, SCM readiness and health.

    This runtime starts only after device enrollment has already been observed
    and durable provisioning state is AGENT_INSTALLING. It preserves the exact
    pre-transfer Hyper-V Guest Service Interface state across crash/retry, binds
    every late-guest step to the stable VMId persisted for this instance, and it
    deliberately does not retire the bootstrap credential; retirement remains
    gated by the later AGENT_HEALTHY checkpoint.
    """

    def __init__(
        self,
        config: ManagedAgentProvisioningConfig,
        transfer_attempt_store: AgentPackageTransferAttemptStore,
    ) -> None:
        config.validate()
        self.config = config
        self.transfer_attempt_store = transfer_attempt_store
        self.registry = InstanceRegistry(config.registry_path)

    def _expected_vm_id(self) -> str:
        record = self.registry.get(self.config.instance_id)
        if record is None:
            raise ManagedAgentProvisioningError(
                "managed instance registry record is missing for late guest Agent runtime"
            )
        if record.backend != "hyperv":
            raise ManagedAgentProvisioningError(
                "managed instance registry backend is not Hyper-V"
            )
        if record.vm_name.casefold() != self.config.vm_name.casefold():
            raise ManagedAgentProvisioningError(
                "managed instance registry VM name does not match late guest runtime"
            )
        if record.vm_id is None:
            raise ManagedAgentProvisioningError(
                "managed instance registry does not contain a stable VMId"
            )
        return _normalize_vm_id(record.vm_id, "persisted VMId")

    def _assert_vm_identity(self) -> str:
        """Read back the exact persisted Hyper-V VMId before any late-guest work."""
        expected_vm_id = self._expected_vm_id()
        result = run_powershell_json(
            f"""
$ErrorActionPreference = 'Stop'
$expectedVmId = [guid]{ps_literal(expected_vm_id)}
$expectedVmName = {ps_literal(self.config.vm_name)}
$vm = Get-VM -Id $expectedVmId -ErrorAction Stop
if ($vm.Name -ine $expectedVmName) {{
  throw 'Persisted Hyper-V VMId resolves to a different VM name'
}}
[pscustomobject]@{{
  vm_id = $vm.Id.Guid
  vm_name = $vm.Name
}}
""".strip(),
            timeout_seconds=30,
        )
        observed_vm_id = _normalize_vm_id(str(result.get("vm_id", "")), "observed VMId")
        observed_vm_name = result.get("vm_name")
        if observed_vm_id != expected_vm_id:
            raise ManagedAgentProvisioningError(
                "observed Hyper-V VMId does not match persisted managed identity"
            )
        if not isinstance(observed_vm_name, str) or (
            observed_vm_name.casefold() != self.config.vm_name.casefold()
        ):
            raise ManagedAgentProvisioningError(
                "observed Hyper-V VM name does not match persisted managed identity"
            )
        return expected_vm_id

    def _load_approved_manifest(self) -> AgentPackageManifest:
        manifest = load_agent_package_manifest(self.config.package_manifest_path)
        canonical = canonical_agent_package_manifest_bytes(manifest)
        if self.config.package_manifest_path.read_bytes() != canonical:
            raise ManagedAgentProvisioningError(
                "approved Agent package manifest is not canonical"
            )
        verify_agent_package(self.config.package_source_root, manifest)
        return manifest

    def _plan(
        self,
        manifest: AgentPackageManifest,
        attempt: AgentPackageTransferAttempt,
    ) -> AgentPackageTransferPlan:
        return AgentPackageTransferPlan.create(
            self.config.package_source_root,
            self.config.package_manifest_path,
            manifest,
            service=self.config.service,
            transfer_id=attempt.transfer_id,
            ownership_token=attempt.ownership_token,
        )

    def _require_transfer_baseline(
        self,
        attempt: AgentPackageTransferAttempt,
    ) -> bool:
        baseline = attempt.guest_service_interface_was_enabled
        if not isinstance(baseline, bool):
            raise ManagedAgentProvisioningError(
                "persisted Guest Service Interface baseline is missing"
            )
        return baseline

    def stage_package(
        self,
        credential: PowerShellDirectCredential,
    ) -> dict[str, object]:
        credential.validate()
        self._assert_vm_identity()
        manifest = self._load_approved_manifest()
        manifest_sha = canonical_agent_package_manifest_sha256(manifest)
        attempt = self.transfer_attempt_store.begin_or_resume(
            instance_id=self.config.instance_id,
            vm_name=self.config.vm_name,
            manifest_sha256=manifest_sha,
        )

        if attempt.phase is AgentPackageTransferPhase.PLANNED:
            if attempt.guest_service_interface_was_enabled is None:
                self._assert_vm_identity()
                baseline = probe_guest_service_interface_enabled(self.config.vm_name)
                attempt = self.transfer_attempt_store.bind_guest_service_interface_baseline(
                    baseline
                )
            attempt = self.transfer_attempt_store.transition(
                AgentPackageTransferPhase.PLANNED,
                AgentPackageTransferPhase.TRANSFERRING,
            )

        baseline = self._require_transfer_baseline(attempt)
        plan = self._plan(manifest, attempt)

        if attempt.phase is AgentPackageTransferPhase.PUBLISHED:
            self._assert_vm_identity()
            restore_guest_service_interface_state(self.config.vm_name, baseline)
            self._assert_vm_identity()
            proof = probe_agent_package_ready(
                self.config.vm_name,
                credential,
                self.config.service,
                manifest,
            )
            if not bool(proof.get("package_ready", False)):
                raise ManagedAgentProvisioningError(
                    "published Agent package attempt no longer has an exact final proof"
                )
            self.transfer_attempt_store.clear_published()
            return {
                "package_ready": True,
                "resumed_published_attempt": True,
                "guest_service_interface_restored": True,
                "file_count": manifest.file_count,
                "total_size": manifest.total_size,
                "entrypoint_sha256": manifest.sha256.lower(),
            }

        if attempt.phase is not AgentPackageTransferPhase.TRANSFERRING:
            raise ManagedAgentProvisioningError("unsupported Agent transfer attempt phase")

        self._assert_vm_identity()
        restore_guest_service_interface_state(self.config.vm_name, baseline)
        self._assert_vm_identity()
        reset_owned_agent_package_staging(
            self.config.vm_name,
            credential,
            plan,
        )
        try:
            self._assert_vm_identity()
            transfer = transfer_agent_package_to_guest(
                self.config.vm_name,
                credential,
                plan,
            )
        finally:
            self._assert_vm_identity()
            restore_guest_service_interface_state(self.config.vm_name, baseline)

        attempt = self.transfer_attempt_store.transition(
            AgentPackageTransferPhase.TRANSFERRING,
            AgentPackageTransferPhase.PUBLISHED,
        )
        _ = attempt

        self._assert_vm_identity()
        proof = probe_agent_package_ready(
            self.config.vm_name,
            credential,
            self.config.service,
            manifest,
        )
        if not bool(proof.get("package_ready", False)):
            raise ManagedAgentProvisioningError(
                "Agent package publication completed without exact package-ready proof"
            )
        self.transfer_attempt_store.clear_published()
        return {
            **transfer,
            "package_ready": True,
            "resumed_published_attempt": False,
            "guest_service_interface_restored": True,
        }

    def install_service(
        self,
        credential: PowerShellDirectCredential,
    ) -> dict[str, object]:
        credential.validate()
        self._assert_vm_identity()
        manifest = self._load_approved_manifest()
        package_proof = probe_agent_package_ready(
            self.config.vm_name,
            credential,
            self.config.service,
            manifest,
        )
        if not bool(package_proof.get("package_ready", False)):
            raise ManagedAgentProvisioningError(
                "HMS Agent service install requires exact package-ready proof"
            )
        self._assert_vm_identity()
        result = install_agent_service(
            self.config.vm_name,
            credential,
            self.config.service,
            package_manifest=manifest,
            runtime_config=self.config.runtime,
        )
        if not bool(result.get("ready", False)):
            raise ManagedAgentProvisioningError("HMS Agent service install did not become ready")
        return result

    def observe(
        self,
        credential: PowerShellDirectCredential,
    ) -> tuple[ProvisionObservation, AgentPostInstallObservation | None]:
        credential.validate()
        self._assert_vm_identity()
        manifest = self._load_approved_manifest()
        package_proof = probe_agent_package_ready(
            self.config.vm_name,
            credential,
            self.config.service,
            manifest,
        )
        package_ready = bool(package_proof.get("package_ready", False))
        if not package_ready:
            return ProvisionObservation(agent_package_ready=False), None

        self._assert_vm_identity()
        post = AgentPostInstallObserver(
            AgentPostInstallObservationConfig(
                vm_name=self.config.vm_name,
                package_manifest=manifest,
                expected_agent_version=manifest.version,
                service=self.config.service,
                runtime=self.config.runtime,
            )
        ).observe(credential)
        return (
            ProvisionObservation(
                agent_package_ready=True,
                agent_service_ready=post.service_ready,
                agent_healthy=post.agent_healthy,
            ),
            post,
        )

    def provision_observation(
        self,
        credential: PowerShellDirectCredential,
    ) -> ProvisionObservation:
        observation, _ = self.observe(credential)
        return observation

    def apply(
        self,
        action: str,
        credential: PowerShellDirectCredential,
    ) -> dict[str, object]:
        if action == "STAGE_HMS_AGENT_PACKAGE":
            return self.stage_package(credential)
        if action == "INSTALL_HMS_AGENT":
            return self.install_service(credential)
        raise NotImplementedError(
            f"managed Agent provisioning runtime does not execute action: {action}"
        )
