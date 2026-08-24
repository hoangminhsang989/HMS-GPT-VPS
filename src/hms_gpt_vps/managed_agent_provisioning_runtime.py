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
from .agent_package_transfer import AgentPackageTransferPlan
from .agent_package_transfer_attempt import (
    AgentPackageTransferAttempt,
    AgentPackageTransferAttemptStore,
    AgentPackageTransferPhase,
)
from .agent_post_install_observe import AgentPostInstallObservation
from .agent_service_install import AgentServiceConfig
from .agent_service_runtime_config import AgentServiceRuntimeConfig
from .instance_registry import InstanceRegistry
from .managed_vm_id_operations import (
    install_agent_service_by_id,
    observe_agent_post_install_by_id,
    probe_agent_package_ready_by_id,
    probe_guest_service_interface_enabled_by_id,
    reset_owned_agent_package_staging_by_id,
    restore_guest_service_interface_state_by_id,
    transfer_agent_package_to_guest_by_id,
)
from .powershell import ps_literal, run_powershell_json
from .powershell_direct import PowerShellDirectCredential
from .provisioning import ProvisionObservation


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


class ManagedAgentProvisioningError(RuntimeError):
    pass


def _same_windows_path(left: str, right: str) -> bool:
    return str(PureWindowsPath(left)).casefold() == str(PureWindowsPath(right)).casefold()


def _path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = path.expanduser().absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            return True
        try:
            stat_result = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = int(getattr(stat_result, "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    return False


def _normalize_vm_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManagedAgentProvisioningError(f"{label} is missing")
    try:
        return str(uuid.UUID(value.strip())).lower()
    except (ValueError, AttributeError) as exc:
        raise ManagedAgentProvisioningError(f"{label} is not a valid GUID") from exc


def _require_true(evidence: dict[str, object], key: str, message: str) -> None:
    """Require an exact JSON boolean true; never accept truthy coercions."""
    if evidence.get(key) is not True:
        raise ManagedAgentProvisioningError(message)


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

        authority_paths = (
            ("Agent package source root", self.package_source_root),
            ("Agent package manifest", self.package_manifest_path),
            ("instance registry", self.registry_path),
        )
        for label, path in authority_paths:
            if _path_chain_has_redirect(path):
                raise ValueError(f"{label} path must not traverse a link or reparse point")
        if not self.package_source_root.is_dir():
            raise FileNotFoundError(self.package_source_root)
        if not self.package_manifest_path.is_file():
            raise FileNotFoundError(self.package_manifest_path)
        if not self.registry_path.is_file():
            raise FileNotFoundError(self.registry_path)


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
        if _path_chain_has_redirect(self.config.registry_path):
            raise ManagedAgentProvisioningError(
                "instance registry authority path traverses a link or reparse point"
            )
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
        # Revalidate lexical package authority on every use. A path that was safe
        # at construction time must not remain trusted if a parent is later
        # replaced by a symlink/junction/reparse redirect.
        if _path_chain_has_redirect(self.config.package_source_root):
            raise ManagedAgentProvisioningError(
                "approved Agent package source authority path traverses a link or reparse point"
            )
        if _path_chain_has_redirect(self.config.package_manifest_path):
            raise ManagedAgentProvisioningError(
                "approved Agent package manifest authority path traverses a link or reparse point"
            )
        if not self.config.package_source_root.is_dir():
            raise ManagedAgentProvisioningError("approved Agent package source root disappeared")
        if not self.config.package_manifest_path.is_file():
            raise ManagedAgentProvisioningError("approved Agent package manifest disappeared")

        manifest = load_agent_package_manifest(self.config.package_manifest_path)
        canonical = canonical_agent_package_manifest_bytes(manifest)
        if self.config.package_manifest_path.read_bytes() != canonical:
            raise ManagedAgentProvisioningError(
                "approved Agent package manifest is not canonical"
            )
        # Check again around the reads so a redirect introduced concurrently is
        # detected before the package can authorize a managed guest mutation.
        if _path_chain_has_redirect(self.config.package_source_root) or _path_chain_has_redirect(
            self.config.package_manifest_path
        ):
            raise ManagedAgentProvisioningError(
                "approved Agent package authority path changed during validation"
            )
        verify_agent_package(self.config.package_source_root, manifest)
        if _path_chain_has_redirect(self.config.package_source_root) or _path_chain_has_redirect(
            self.config.package_manifest_path
        ):
            raise ManagedAgentProvisioningError(
                "approved Agent package authority path changed during verification"
            )
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
                vm_id = self._assert_vm_identity()
                baseline = probe_guest_service_interface_enabled_by_id(
                    vm_id,
                    self.config.vm_name,
                )
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
            vm_id = self._assert_vm_identity()
            restore_guest_service_interface_state_by_id(
                vm_id,
                self.config.vm_name,
                baseline,
            )
            vm_id = self._assert_vm_identity()
            proof = probe_agent_package_ready_by_id(
                vm_id,
                self.config.vm_name,
                credential,
                self.config.service,
                manifest,
            )
            _require_true(
                proof,
                "package_ready",
                "published Agent package attempt no longer has an exact final proof",
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

        vm_id = self._assert_vm_identity()
        restore_guest_service_interface_state_by_id(
            vm_id,
            self.config.vm_name,
            baseline,
        )
        vm_id = self._assert_vm_identity()
        reset_owned_agent_package_staging_by_id(
            vm_id,
            self.config.vm_name,
            credential,
            plan,
        )
        try:
            vm_id = self._assert_vm_identity()
            transfer = transfer_agent_package_to_guest_by_id(
                vm_id,
                self.config.vm_name,
                credential,
                plan,
            )
        finally:
            vm_id = self._assert_vm_identity()
            restore_guest_service_interface_state_by_id(
                vm_id,
                self.config.vm_name,
                baseline,
            )

        attempt = self.transfer_attempt_store.transition(
            AgentPackageTransferPhase.TRANSFERRING,
            AgentPackageTransferPhase.PUBLISHED,
        )
        _ = attempt

        vm_id = self._assert_vm_identity()
        proof = probe_agent_package_ready_by_id(
            vm_id,
            self.config.vm_name,
            credential,
            self.config.service,
            manifest,
        )
        _require_true(
            proof,
            "package_ready",
            "Agent package publication completed without exact package-ready proof",
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
        vm_id = self._assert_vm_identity()
        manifest = self._load_approved_manifest()
        package_proof = probe_agent_package_ready_by_id(
            vm_id,
            self.config.vm_name,
            credential,
            self.config.service,
            manifest,
        )
        _require_true(
            package_proof,
            "package_ready",
            "HMS Agent service install requires exact package-ready proof",
        )
        vm_id = self._assert_vm_identity()
        result = install_agent_service_by_id(
            vm_id,
            self.config.vm_name,
            credential,
            self.config.service,
            package_manifest=manifest,
            runtime_config=self.config.runtime,
        )
        _require_true(
            result,
            "ready",
            "HMS Agent service install did not become ready",
        )
        return result

    def observe(
        self,
        credential: PowerShellDirectCredential,
    ) -> tuple[ProvisionObservation, AgentPostInstallObservation | None]:
        credential.validate()
        vm_id = self._assert_vm_identity()
        manifest = self._load_approved_manifest()
        package_proof = probe_agent_package_ready_by_id(
            vm_id,
            self.config.vm_name,
            credential,
            self.config.service,
            manifest,
        )
        package_ready = package_proof.get("package_ready") is True
        if not package_ready:
            return ProvisionObservation(agent_package_ready=False), None

        vm_id = self._assert_vm_identity()
        post = observe_agent_post_install_by_id(
            vm_id,
            self.config.vm_name,
            credential,
            package_manifest=manifest,
            expected_agent_version=manifest.version,
            service=self.config.service,
            runtime=self.config.runtime,
        )
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
