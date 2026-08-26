from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import ssl
import sys
from typing import Mapping

from .agent_device_credential_store import BridgeAgentDeviceCredentialStore
from .agent_package import load_agent_package_manifest, verify_agent_package
from .agent_service_runtime_config import load_agent_service_runtime_config
from .bridge_composite_activation_runner import (
    BOOTSTRAP_PASSWORD_ENV,
    BOOTSTRAP_USERNAME_ENV,
    require_windows_administrator,
)
from .bridge_production_assembly import BridgeRuntimeLayout
from .bridge_runtime_layout_provisioning import (
    DEFAULT_BRIDGE_PROVISION_STATE_PATH,
    DEFAULT_BRIDGE_RUNTIME_ROOT,
    validate_bridge_runtime_layout_authority,
)
from .bridge_service_config_storage import (
    DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
    load_protected_bridge_service_runtime_config,
)
from .bridge_service_provisioning_identity import (
    prove_hms_bridge_provisioning_identity,
)
from .external_mcp_command_flow_contract import (
    canonical_git_sha1,
    canonical_sha256,
    qualification_path,
)
from .hyperv_network import HyperVNetworkConfig
from .hyperv_probe import probe_hyperv_host
from .instance_registry import InstanceRegistry
from .powershell import run_powershell_json
from .provision_state import ProvisionState, ProvisionStateStore
from .qualification_file_authority import (
    path_chain_has_redirect,
    read_file_pinned,
    require_existing_directory,
    write_json_create_only,
)
from .r002f_one_shot_production_qualification import (
    R002FOneShotProductionQualificationRequest,
    require_exact_clean_checkout,
)

_SCHEMA_VERSION = 1
_MAX_PUBLIC_CERTIFICATE_BYTES = 256 * 1024
_MAX_PREFLIGHT_PROOF_BYTES = 128 * 1024
_ALLOWED_PROVISION_STATES = frozenset(
    {
        ProvisionState.AGENT_INSTALLING,
        ProvisionState.AGENT_SERVICE_READY,
        ProvisionState.AGENT_HEALTHY,
    }
)
_OPTIONAL_AUTHORITY_NAMES = (
    "package_root",
    "package_manifest",
    "runtime_config",
    "instance_registry",
    "instance_runtime_dir",
    "bridge_device_credential",
    "trust_root_certificate",
)
_REQUIRED_CHALLENGE_NAMES = (
    "challenge_source_commit",
    "challenge_workspace_path",
    "challenge_expected_sha256",
)


class R002FExecutionPreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class R002FExecutionPreflightRequest:
    repo_root: Path
    proof_path: Path
    run_dir: Path | None = None
    package_root: Path | None = None
    package_manifest: Path | None = None
    runtime_config: Path | None = None
    instance_registry: Path | None = None
    instance_runtime_dir: Path | None = None
    bridge_device_credential: Path | None = None
    trust_root_certificate: Path | None = None
    challenge_source_commit: str | None = None
    challenge_workspace_path: str | None = None
    challenge_expected_sha256: str | None = None
    max_reconcile_steps: int = 8
    external_timeout_seconds: float = 300.0
    step_timeout_seconds: float = 900.0

    def validate_shape(self) -> None:
        if not isinstance(self.repo_root, Path) or not isinstance(self.proof_path, Path):
            raise TypeError("repo_root and proof_path must be pathlib.Path")
        if self.run_dir is not None and not isinstance(self.run_dir, Path):
            raise TypeError("run_dir must be pathlib.Path or None")
        for name in _OPTIONAL_AUTHORITY_NAMES:
            value = getattr(self, name)
            if value is not None and not isinstance(value, Path):
                raise TypeError(f"{name} must be pathlib.Path or None")
        for name in _REQUIRED_CHALLENGE_NAMES:
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be str or None")
        if (
            not isinstance(self.max_reconcile_steps, int)
            or isinstance(self.max_reconcile_steps, bool)
            or not 1 <= self.max_reconcile_steps <= 32
        ):
            raise ValueError("max_reconcile_steps must be between 1 and 32")
        for name in ("external_timeout_seconds", "step_timeout_seconds"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise TypeError(f"{name} must be numeric")
            value = float(value)
            if value <= 0.0 or value != value or value in {float("inf"), float("-inf")}:
                raise ValueError(f"{name} must be positive and finite")
        if float(self.step_timeout_seconds) <= float(self.external_timeout_seconds):
            raise ValueError(
                "step_timeout_seconds must be greater than external_timeout_seconds"
            )


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def render_powershell_command(argv: list[str]) -> str:
    if not isinstance(argv, list) or not argv or any(
        not isinstance(value, str) or not value for value in argv
    ):
        raise ValueError("argv must be a non-empty list of strings")
    return "& " + " ".join(_powershell_quote(value) for value in argv)


def _lexically_within(child: Path, parent: Path) -> bool:
    child_text = os.path.normcase(os.path.abspath(str(child.expanduser().absolute())))
    parent_text = os.path.normcase(os.path.abspath(str(parent.expanduser().absolute())))
    try:
        return os.path.commonpath([child_text, parent_text]) == parent_text
    except ValueError:
        return False


def _derive_run_dir(request: R002FExecutionPreflightRequest, source_commit: str) -> Path:
    if request.run_dir is not None:
        return request.run_dir.expanduser().absolute()
    parent = request.proof_path.expanduser().absolute().parent
    return parent / f"r002f-one-shot-{source_commit[:12]}"


def _safe_existing_file(path: Path, *, label: str, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    authority = path.expanduser().absolute()
    if path_chain_has_redirect(authority):
        raise R002FExecutionPreflightError(f"{label} authority is redirected")
    return read_file_pinned(
        authority,
        max_bytes=max_bytes,
        label=label,
        allow_empty=False,
    )


def _pem_certificate_der_sha256(path: Path) -> str:
    raw = _safe_existing_file(
        path,
        label="managed guest trust-root certificate",
        max_bytes=_MAX_PUBLIC_CERTIFICATE_BYTES,
    )
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise R002FExecutionPreflightError(
            "managed guest trust-root certificate is not ASCII PEM"
        ) from exc
    if text.count("-----BEGIN CERTIFICATE-----") != 1 or text.count(
        "-----END CERTIFICATE-----"
    ) != 1:
        raise R002FExecutionPreflightError(
            "managed guest trust-root file must contain exactly one certificate"
        )
    try:
        der = ssl.PEM_cert_to_DER_cert(text)
    except ValueError as exc:
        raise R002FExecutionPreflightError(
            "managed guest trust-root certificate is invalid"
        ) from exc
    return hashlib.sha256(der).hexdigest()


def derive_trust_root_certificate_path(
    *,
    configured_path: Path | None,
    tls_certificate_path: str,
    tls_certificate_der_sha256: str,
    trust_root_der_sha256: str,
) -> Path | None:
    """Use the server certificate automatically only when bytes are authority-equal.

    A different trust-root digest is a separate deployment authority and must be
    supplied explicitly. The preflight never searches the filesystem for a
    certificate based only on a digest because such a search would create an
    attacker-selectable authority boundary.
    """

    if configured_path is not None:
        return configured_path.expanduser().absolute()
    if tls_certificate_der_sha256 == trust_root_der_sha256:
        return Path(tls_certificate_path).expanduser().absolute()
    return None


def _probe_exact_vm(vm_id: str, vm_name: str) -> dict[str, object]:
    result = run_powershell_json(
        """
$ErrorActionPreference = 'Stop'
$vm = Get-VM -Id ([guid]'%s') -ErrorAction Stop
[pscustomobject]@{
  vm_id = [string]$vm.Id.Guid.ToLowerInvariant()
  vm_name = [string]$vm.Name
  state = [string]$vm.State
}
""" % vm_id.replace("'", "''"),
        timeout_seconds=30,
    )
    if frozenset(result) != frozenset({"vm_id", "vm_name", "state"}):
        raise R002FExecutionPreflightError("managed VM readback schema is invalid")
    if result.get("vm_id") != vm_id or result.get("vm_name") != vm_name:
        raise R002FExecutionPreflightError(
            "managed VM identity differs from Bridge runtime config"
        )
    state = result.get("state")
    if not isinstance(state, str) or not state:
        raise R002FExecutionPreflightError("managed VM state readback is invalid")
    return dict(result)


def _repo_environment(environment: Mapping[str, str]) -> dict[str, str]:
    env = {str(key): str(value) for key, value in environment.items()}
    env.pop(BOOTSTRAP_USERNAME_ENV, None)
    env.pop(BOOTSTRAP_PASSWORD_ENV, None)
    return env


def _required_path_names(request: R002FExecutionPreflightRequest) -> list[str]:
    return [
        name
        for name in (
            "package_root",
            "package_manifest",
            "runtime_config",
            "instance_registry",
            "instance_runtime_dir",
            "bridge_device_credential",
        )
        if getattr(request, name) is None
    ]


def _required_challenge_names(request: R002FExecutionPreflightRequest) -> list[str]:
    return [
        name for name in _REQUIRED_CHALLENGE_NAMES if getattr(request, name) is None
    ]


def build_one_shot_argv(
    *,
    request: R002FExecutionPreflightRequest,
    runner_source_commit: str,
    instance_id: str,
    vm_name: str,
    run_dir: Path,
    provision_state: Path,
    trust_root_certificate: Path,
) -> list[str]:
    missing = _required_path_names(request) + _required_challenge_names(request)
    if missing:
        raise R002FExecutionPreflightError(
            "cannot build one-shot argv while authorities are missing"
        )
    assert request.package_root is not None
    assert request.package_manifest is not None
    assert request.runtime_config is not None
    assert request.instance_registry is not None
    assert request.instance_runtime_dir is not None
    assert request.bridge_device_credential is not None
    assert request.challenge_source_commit is not None
    assert request.challenge_workspace_path is not None
    assert request.challenge_expected_sha256 is not None
    argv = [
        sys.executable,
        str(
            request.repo_root.expanduser().absolute()
            / "scripts"
            / "run_r002f_one_shot_production_qualification.py"
        ),
        "--repo-root",
        str(request.repo_root.expanduser().absolute()),
        "--run-dir",
        str(run_dir),
        "--runner-source-commit",
        runner_source_commit,
        "--instance-id",
        instance_id,
        "--vm-name",
        vm_name,
        "--package-root",
        str(request.package_root.expanduser().absolute()),
        "--package-manifest",
        str(request.package_manifest.expanduser().absolute()),
        "--runtime-config",
        str(request.runtime_config.expanduser().absolute()),
        "--instance-registry",
        str(request.instance_registry.expanduser().absolute()),
        "--provision-state",
        str(provision_state),
        "--instance-runtime-dir",
        str(request.instance_runtime_dir.expanduser().absolute()),
        "--bridge-device-credential",
        str(request.bridge_device_credential.expanduser().absolute()),
        "--trust-root-certificate",
        str(trust_root_certificate),
        "--challenge-source-commit",
        request.challenge_source_commit,
        "--challenge-workspace-path",
        request.challenge_workspace_path,
        "--challenge-expected-sha256",
        request.challenge_expected_sha256,
        "--max-reconcile-steps",
        str(request.max_reconcile_steps),
        "--external-timeout",
        str(float(request.external_timeout_seconds)),
        "--step-timeout",
        str(float(request.step_timeout_seconds)),
    ]
    if any(
        BOOTSTRAP_USERNAME_ENV in value or BOOTSTRAP_PASSWORD_ENV in value
        for value in argv
    ):
        raise R002FExecutionPreflightError(
            "one-shot argv unexpectedly contains bootstrap environment names"
        )
    return argv


def _blocked_manifest(
    *,
    runner_source_commit: str | None,
    missing_authority: list[str],
    host_blockers: list[str],
    authority_blockers: list[str],
    derived: dict[str, object],
    bootstrap_secret_environment_absent: bool,
) -> dict[str, object]:
    if missing_authority:
        status = "BLOCKED_MISSING_AUTHORITY"
    elif host_blockers:
        status = "BLOCKED_HOST_PRECONDITION"
    else:
        status = "BLOCKED_AUTHORITY_MISMATCH"
    return {
        "schema_version": _SCHEMA_VERSION,
        "qualification": "R002F_ZERO_MANUAL_EXECUTION_PREFLIGHT",
        "status": status,
        "ready": False,
        "runner_source_commit": runner_source_commit,
        "missing_authority": sorted(set(missing_authority)),
        "host_blockers": sorted(set(host_blockers)),
        "authority_blockers": sorted(set(authority_blockers)),
        "derived": derived,
        "bootstrap_secret_environment_absent": bootstrap_secret_environment_absent,
        "bootstrap_environment_required_at_execution": True,
        "bootstrap_environment_names": [
            BOOTSTRAP_USERNAME_ENV,
            BOOTSTRAP_PASSWORD_ENV,
        ],
        "one_shot_argv": None,
        "one_shot_powershell": None,
        "execution_started": False,
        "hyperv_mutated": False,
        "bridge_started": False,
        "tunnel_started": False,
    }


def run_r002f_execution_preflight(
    request: R002FExecutionPreflightRequest,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Read-only Windows preflight for the staged one-shot production qualification.

    The function intentionally does not start HMSBridge, HMSAgent, Hyper-V VMs or
    the OpenAI tunnel. It never reads bootstrap secret values into the published
    artifact and never guesses host-side paths that are not bound by existing
    production authority.
    """

    if not isinstance(request, R002FExecutionPreflightRequest):
        raise TypeError("request must be R002FExecutionPreflightRequest")
    request.validate_shape()
    env = os.environ if environment is None else environment
    proof_path = request.proof_path.expanduser().absolute()
    repo_root = request.repo_root.expanduser().absolute()
    if proof_path.exists() or proof_path.is_symlink():
        raise FileExistsError("preflight proof path must be new")
    require_existing_directory(proof_path.parent, label="preflight proof parent")
    if path_chain_has_redirect(proof_path) or path_chain_has_redirect(proof_path.parent):
        raise PermissionError("preflight proof authority is redirected")
    if _lexically_within(proof_path, repo_root):
        raise ValueError("preflight proof must be outside the source checkout")

    missing_authority = _required_path_names(request) + _required_challenge_names(request)
    host_blockers: list[str] = []
    authority_blockers: list[str] = []
    derived: dict[str, object] = {
        "bridge_runtime_config_path": str(DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH),
        "bridge_runtime_root": str(DEFAULT_BRIDGE_RUNTIME_ROOT),
        "bridge_provision_state_path": str(DEFAULT_BRIDGE_PROVISION_STATE_PATH),
    }
    # Do not run unrelated PowerShell/Git probes while bootstrap secrets are in
    # this process environment. Existing shared helpers inherit os.environ.
    # The one-shot runner consumes these values later; preflight must be run
    # before setting them (or after removing them) so read-only child processes
    # cannot inherit credentials they do not need.
    secret_env_present = any(
        isinstance(env.get(name), str) and bool(str(env.get(name, "")))
        for name in (BOOTSTRAP_USERNAME_ENV, BOOTSTRAP_PASSWORD_ENV)
    ) or any(
        isinstance(os.environ.get(name), str) and bool(str(os.environ.get(name, "")))
        for name in (BOOTSTRAP_USERNAME_ENV, BOOTSTRAP_PASSWORD_ENV)
    )
    if secret_env_present:
        host_blockers.append(
            "BOOTSTRAP_SECRET_ENVIRONMENT_MUST_BE_ABSENT_DURING_PREFLIGHT"
        )

    runner_source_commit: str | None = None
    if secret_env_present:
        proof = _blocked_manifest(
            runner_source_commit=None,
            missing_authority=missing_authority,
            host_blockers=host_blockers,
            authority_blockers=[],
            derived=derived,
            bootstrap_secret_environment_absent=False,
        )
        write_json_create_only(
            proof_path,
            proof,
            max_bytes=_MAX_PREFLIGHT_PROOF_BYTES,
            label="R002F zero-manual execution preflight",
        )
        return proof

    try:
        runner_source_commit = canonical_git_sha1(
            subprocess_git_head(repo_root, environment=_repo_environment(env))
        )
        require_exact_clean_checkout(
            repo_root,
            runner_source_commit,
            environment=_repo_environment(env),
        )
    except Exception:
        authority_blockers.append("SOURCE_CHECKOUT_NOT_EXACT_CLEAN")

    try:
        require_windows_administrator()
    except Exception:
        host_blockers.append("WINDOWS_ADMINISTRATOR_REQUIRED")

    try:
        hyperv = probe_hyperv_host().state
        hyperv.validate()
        derived["hyperv_available"] = hyperv.hyperv_available
        derived["hyperv_enabled"] = hyperv.hyperv_enabled
        derived["virtualization_firmware_enabled"] = (
            hyperv.virtualization_firmware_enabled
        )
        derived["restart_required"] = hyperv.restart_required
        if not (
            hyperv.is_windows
            and hyperv.hyperv_available
            and hyperv.hyperv_enabled
            and hyperv.virtualization_firmware_enabled
            and not hyperv.restart_required
        ):
            host_blockers.append("HYPERV_HOST_NOT_READY")
    except Exception:
        host_blockers.append("HYPERV_HOST_PROBE_FAILED")

    bridge_config = None
    try:
        bridge_config = load_protected_bridge_service_runtime_config()
        validate_bridge_runtime_layout_authority(bridge_config)
        layout = BridgeRuntimeLayout.prepare(Path(bridge_config.runtime_root))
        if (
            str(layout.root).casefold()
            != str(Path(DEFAULT_BRIDGE_RUNTIME_ROOT).expanduser().absolute()).casefold()
        ):
            raise R002FExecutionPreflightError("Bridge runtime layout root differs")
        derived.update(
            {
                "instance_id": bridge_config.instance_id,
                "vm_id": bridge_config.vm_id,
                "vm_name": bridge_config.vm_name,
                "tunnel_id": bridge_config.tunnel_id,
                "mcp_port": bridge_config.mcp_port,
                "tls_port": bridge_config.tls_port,
                "trust_root_der_sha256": bridge_config.trust_root_der_sha256,
            }
        )
        if (
            str(Path(bridge_config.provision_state_path)).casefold()
            != str(Path(DEFAULT_BRIDGE_PROVISION_STATE_PATH)).casefold()
        ):
            raise R002FExecutionPreflightError(
                "Bridge provision state differs from fixed authority"
            )
    except Exception:
        authority_blockers.append("BRIDGE_RUNTIME_CONFIG_OR_LAYOUT_INVALID")

    try:
        identity = prove_hms_bridge_provisioning_identity()
        derived["bridge_service_state"] = identity.get("service_state")
        derived["bridge_service_start_mode"] = identity.get("service_start_mode")
        if (
            identity.get("service_state") != "Stopped"
            or identity.get("service_start_mode") != "Manual"
        ):
            host_blockers.append("HMSBRIDGE_NOT_STOPPED_MANUAL")
    except Exception:
        host_blockers.append("HMSBRIDGE_IDENTITY_PROBE_FAILED")

    trust_root: Path | None = None
    provision_state = Path(DEFAULT_BRIDGE_PROVISION_STATE_PATH)
    if bridge_config is not None:
        trust_root = derive_trust_root_certificate_path(
            configured_path=request.trust_root_certificate,
            tls_certificate_path=bridge_config.tls_certificate_path,
            tls_certificate_der_sha256=bridge_config.tls_certificate_der_sha256,
            trust_root_der_sha256=bridge_config.trust_root_der_sha256,
        )
        if trust_root is None:
            missing_authority.append("trust_root_certificate")
        else:
            try:
                observed = _pem_certificate_der_sha256(trust_root)
                if observed != bridge_config.trust_root_der_sha256:
                    raise R002FExecutionPreflightError(
                        "trust-root certificate SHA-256 differs"
                    )
                derived["trust_root_certificate_path"] = str(trust_root)
                derived["trust_root_certificate_sha256_proven"] = True
            except Exception:
                authority_blockers.append("TRUST_ROOT_CERTIFICATE_INVALID")

        try:
            vm = _probe_exact_vm(bridge_config.vm_id, bridge_config.vm_name)
            derived["vm_state"] = vm["state"]
        except Exception:
            host_blockers.append("MANAGED_VM_IDENTITY_PROBE_FAILED")

        if request.runtime_config is not None:
            try:
                agent_config = load_agent_service_runtime_config(
                    request.runtime_config.expanduser().absolute()
                )
                expected_origin = (
                    f"https://{HyperVNetworkConfig().gateway}:{bridge_config.tls_port}"
                )
                if (
                    agent_config.instance_id != bridge_config.instance_id
                    or agent_config.bridge_origin != expected_origin
                ):
                    raise R002FExecutionPreflightError(
                        "Agent runtime config differs from Bridge authority"
                    )
                derived["agent_runtime_config_bound"] = True
                derived["agent_project_id"] = agent_config.project_id
            except Exception:
                authority_blockers.append("AGENT_RUNTIME_CONFIG_INVALID")

        if request.instance_registry is not None:
            try:
                record = InstanceRegistry(
                    request.instance_registry.expanduser().absolute()
                ).get(bridge_config.instance_id)
                if (
                    record is None
                    or record.vm_id != bridge_config.vm_id
                    or record.vm_name != bridge_config.vm_name
                ):
                    raise R002FExecutionPreflightError(
                        "instance registry differs from Bridge VM authority"
                    )
                derived["instance_registry_bound"] = True
            except Exception:
                authority_blockers.append("INSTANCE_REGISTRY_INVALID")

        try:
            state_record = ProvisionStateStore(provision_state).load()
            if (
                state_record is None
                or state_record.instance_id != bridge_config.instance_id
                or state_record.state not in _ALLOWED_PROVISION_STATES
            ):
                raise R002FExecutionPreflightError(
                    "provision state is not at a one-shot managed-Agent checkpoint"
                )
            derived["provision_state"] = state_record.state.value
        except Exception:
            authority_blockers.append("PROVISION_STATE_INVALID")

        if request.bridge_device_credential is not None:
            try:
                store = BridgeAgentDeviceCredentialStore(
                    request.bridge_device_credential.expanduser().absolute()
                )
                credential = store.load(expected_instance_id=bridge_config.instance_id)
                credential.validate()
                derived["bridge_device_credential_bound"] = True
            except Exception:
                authority_blockers.append("BRIDGE_DEVICE_CREDENTIAL_INVALID")

    if request.package_root is not None and request.package_manifest is not None:
        try:
            root = require_existing_directory(
                request.package_root,
                label="Agent package root",
            )
            manifest = load_agent_package_manifest(
                request.package_manifest.expanduser().absolute()
            )
            verify_agent_package(root, manifest)
            derived["agent_package_tree_proven"] = True
        except Exception:
            authority_blockers.append("AGENT_PACKAGE_AUTHORITY_INVALID")

    if request.instance_runtime_dir is not None:
        try:
            require_existing_directory(
                request.instance_runtime_dir,
                label="instance runtime directory",
            )
            derived["instance_runtime_directory_proven"] = True
        except Exception:
            authority_blockers.append("INSTANCE_RUNTIME_DIRECTORY_INVALID")

    if request.challenge_source_commit is not None:
        try:
            canonical_git_sha1(request.challenge_source_commit)
        except Exception:
            authority_blockers.append("CHALLENGE_SOURCE_COMMIT_INVALID")
    if request.challenge_workspace_path is not None:
        try:
            qualification_path(request.challenge_workspace_path)
        except Exception:
            authority_blockers.append("CHALLENGE_WORKSPACE_PATH_INVALID")
    if request.challenge_expected_sha256 is not None:
        try:
            canonical_sha256(
                request.challenge_expected_sha256,
                "challenge_expected_sha256",
            )
        except Exception:
            authority_blockers.append("CHALLENGE_EXPECTED_SHA256_INVALID")

    missing_authority = sorted(set(missing_authority))
    if (
        runner_source_commit is None
        or bridge_config is None
        or trust_root is None
        or missing_authority
        or host_blockers
        or authority_blockers
    ):
        proof = _blocked_manifest(
            runner_source_commit=runner_source_commit,
            missing_authority=missing_authority,
            host_blockers=host_blockers,
            authority_blockers=authority_blockers,
            derived=derived,
            bootstrap_secret_environment_absent=not secret_env_present,
        )
        write_json_create_only(
            proof_path,
            proof,
            max_bytes=_MAX_PREFLIGHT_PROOF_BYTES,
            label="R002F zero-manual execution preflight",
        )
        return proof

    run_dir = _derive_run_dir(request, runner_source_commit)
    if run_dir.exists() or run_dir.is_symlink():
        host_blockers.append("ONE_SHOT_RUN_DIRECTORY_ALREADY_EXISTS")
    if path_chain_has_redirect(run_dir) or path_chain_has_redirect(run_dir.parent):
        authority_blockers.append("ONE_SHOT_RUN_DIRECTORY_REDIRECTED")
    try:
        require_existing_directory(run_dir.parent, label="one-shot run parent")
    except Exception:
        host_blockers.append("ONE_SHOT_RUN_PARENT_MISSING")
    if host_blockers or authority_blockers:
        proof = _blocked_manifest(
            runner_source_commit=runner_source_commit,
            missing_authority=[],
            host_blockers=host_blockers,
            authority_blockers=authority_blockers,
            derived=derived,
            bootstrap_secret_environment_absent=not secret_env_present,
        )
        write_json_create_only(
            proof_path,
            proof,
            max_bytes=_MAX_PREFLIGHT_PROOF_BYTES,
            label="R002F zero-manual execution preflight",
        )
        return proof

    one_shot = R002FOneShotProductionQualificationRequest(
        repo_root=repo_root,
        run_dir=run_dir,
        runner_source_commit=runner_source_commit,
        instance_id=bridge_config.instance_id,
        vm_name=bridge_config.vm_name,
        package_root=request.package_root,
        package_manifest=request.package_manifest,
        runtime_config=request.runtime_config,
        instance_registry=request.instance_registry,
        provision_state=provision_state,
        instance_runtime_dir=request.instance_runtime_dir,
        bridge_device_credential=request.bridge_device_credential,
        trust_root_certificate=trust_root,
        challenge_source_commit=request.challenge_source_commit,
        challenge_workspace_path=request.challenge_workspace_path,
        challenge_expected_sha256=request.challenge_expected_sha256,
        max_reconcile_steps=request.max_reconcile_steps,
        external_timeout_seconds=request.external_timeout_seconds,
        step_timeout_seconds=request.step_timeout_seconds,
    )
    one_shot.validate()
    argv = build_one_shot_argv(
        request=request,
        runner_source_commit=runner_source_commit,
        instance_id=bridge_config.instance_id,
        vm_name=bridge_config.vm_name,
        run_dir=run_dir,
        provision_state=provision_state,
        trust_root_certificate=trust_root,
    )
    proof = {
        "schema_version": _SCHEMA_VERSION,
        "qualification": "R002F_ZERO_MANUAL_EXECUTION_PREFLIGHT",
        "status": "READY_FOR_ONE_SHOT_EXECUTION",
        "ready": True,
        "runner_source_commit": runner_source_commit,
        "missing_authority": [],
        "host_blockers": [],
        "authority_blockers": [],
        "derived": derived,
        "bootstrap_secret_environment_absent": True,
        "bootstrap_environment_required_at_execution": True,
        "bootstrap_environment_names": [
            BOOTSTRAP_USERNAME_ENV,
            BOOTSTRAP_PASSWORD_ENV,
        ],
        "one_shot_argv": argv,
        "one_shot_powershell": render_powershell_command(argv),
        "execution_started": False,
        "hyperv_mutated": False,
        "bridge_started": False,
        "tunnel_started": False,
    }
    write_json_create_only(
        proof_path,
        proof,
        max_bytes=_MAX_PREFLIGHT_PROOF_BYTES,
        label="R002F zero-manual execution preflight",
    )
    return proof


def subprocess_git_head(
    repo_root: Path,
    *,
    environment: Mapping[str, str],
) -> str:
    import subprocess

    completed = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", "HEAD"],
        cwd=str(repo_root),
        env=dict(environment),
        capture_output=True,
        text=True,
        check=False,
        timeout=60.0,
    )
    if completed.returncode != 0:
        raise R002FExecutionPreflightError("could not resolve qualification checkout HEAD")
    return completed.stdout.strip()
