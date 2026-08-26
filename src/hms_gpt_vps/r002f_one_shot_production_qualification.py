from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable, Mapping, MutableMapping, Sequence

from .bridge_composite_activation_runner import (
    BOOTSTRAP_PASSWORD_ENV,
    BOOTSTRAP_USERNAME_ENV,
    require_windows_administrator,
)
from .external_mcp_command_flow_contract import (
    canonical_git_sha1,
    canonical_sha256,
    identifier,
    qualification_path,
)
from .qualification_file_authority import (
    path_chain_has_redirect,
    read_file_pinned,
    require_existing_directory,
    write_json_create_only,
)
from .r002f_production_proof_gate import verify_r002f_production_proof_bundle

_PROOF_SCHEMA_VERSION = 1
_MAX_PROOF_BYTES = 64 * 1024
_MAX_COMPONENT_PROOF_BYTES = 128 * 1024
_MIN_STEP_TIMEOUT_SECONDS = 30.0
_MAX_STEP_TIMEOUT_SECONDS = 3600.0

MANAGED_HYPERV_PROOF_NAME = "01-managed-hyperv.json"
COMPOSITE_ACTIVATION_PROOF_NAME = "02-composite-activation.json"
AGENT_TRANSPORT_PROOF_NAME = "03-authenticated-agent-transport.json"
OPENAI_CONTROL_PLANE_PROOF_NAME = "04-openai-control-plane.json"
OPENAI_CHALLENGE_NAME = "04-openai-control-plane-challenge.json"
CROSS_PROOF_NAME = "05-cross-proof.json"
FINAL_MANIFEST_NAME = "06-one-shot-manifest.json"
FAILURE_MARKER_NAME = "qualification-failure.json"


class R002FOneShotProductionQualificationError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        step: str,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.step = step
        self.exit_code = exit_code


def _canonical_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_nonempty_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    return value.strip()


def _require_positive_finite_timeout(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    normalized = float(value)
    if (
        not (normalized == normalized)
        or normalized in {float("inf"), float("-inf")}
        or normalized < _MIN_STEP_TIMEOUT_SECONDS
        or normalized > _MAX_STEP_TIMEOUT_SECONDS
    ):
        raise ValueError(
            f"{label} must be between "
            f"{_MIN_STEP_TIMEOUT_SECONDS:.0f} and {_MAX_STEP_TIMEOUT_SECONDS:.0f} seconds"
        )
    return normalized


def _require_existing_regular_file(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} must be pathlib.Path")
    authority = path.expanduser().absolute()
    if path_chain_has_redirect(authority):
        raise PermissionError(f"{label} must not traverse a link or reparse point")
    try:
        current = authority.stat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(authority) from exc
    if not stat.S_ISREG(current.st_mode) or not authority.is_file():
        raise PermissionError(f"{label} must be an existing regular file")
    return authority


def _lexically_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_environment_without_bootstrap(
    source: Mapping[str, str],
) -> dict[str, str]:
    env = {str(key): str(value) for key, value in source.items()}
    env.pop(BOOTSTRAP_USERNAME_ENV, None)
    env.pop(BOOTSTRAP_PASSWORD_ENV, None)
    return env


@dataclass(frozen=True)
class R002FOneShotProductionQualificationRequest:
    repo_root: Path
    run_dir: Path
    runner_source_commit: str
    instance_id: str
    vm_name: str
    package_root: Path
    package_manifest: Path
    runtime_config: Path
    instance_registry: Path
    provision_state: Path
    instance_runtime_dir: Path
    bridge_device_credential: Path
    trust_root_certificate: Path
    challenge_source_commit: str
    challenge_workspace_path: str
    challenge_expected_sha256: str
    max_reconcile_steps: int = 8
    external_timeout_seconds: float = 300.0
    step_timeout_seconds: float = 900.0

    def validate(self) -> None:
        if not isinstance(self.repo_root, Path) or not isinstance(self.run_dir, Path):
            raise TypeError("repo_root and run_dir must be pathlib.Path")
        canonical_git_sha1(self.runner_source_commit)
        canonical_git_sha1(self.challenge_source_commit)
        identifier(self.instance_id, "instance_id")
        _require_nonempty_text(self.vm_name, "vm_name")
        qualification_path(self.challenge_workspace_path)
        canonical_sha256(self.challenge_expected_sha256, "challenge_expected_sha256")
        if (
            not isinstance(self.max_reconcile_steps, int)
            or isinstance(self.max_reconcile_steps, bool)
            or self.max_reconcile_steps < 1
            or self.max_reconcile_steps > 32
        ):
            raise ValueError("max_reconcile_steps must be between 1 and 32")
        external = _require_positive_finite_timeout(
            self.external_timeout_seconds,
            "external_timeout_seconds",
        )
        step = _require_positive_finite_timeout(
            self.step_timeout_seconds,
            "step_timeout_seconds",
        )
        if step <= external:
            raise ValueError(
                "step_timeout_seconds must be greater than external_timeout_seconds"
            )

        repo_root = require_existing_directory(self.repo_root, label="qualification repo root")
        source_root = require_existing_directory(repo_root / "src", label="qualification src root")
        scripts_root = require_existing_directory(
            repo_root / "scripts",
            label="qualification scripts root",
        )
        if source_root.parent != repo_root or scripts_root.parent != repo_root:
            raise ValueError("qualification source/script roots are not direct repo children")

        run_dir = self.run_dir.expanduser().absolute()
        if run_dir.exists() or run_dir.is_symlink():
            raise FileExistsError("qualification run_dir must not already exist")
        parent = require_existing_directory(run_dir.parent, label="qualification run parent")
        if _lexically_within(run_dir, repo_root):
            raise ValueError("qualification run_dir must be outside the source checkout")
        if path_chain_has_redirect(run_dir) or path_chain_has_redirect(parent):
            raise PermissionError(
                "qualification run_dir must not traverse a link or reparse point"
            )

        require_existing_directory(self.package_root, label="Agent package root")
        require_existing_directory(self.instance_runtime_dir, label="instance runtime directory")
        for path, label in (
            (self.package_manifest, "Agent package manifest"),
            (self.runtime_config, "Agent runtime config"),
            (self.instance_registry, "instance registry"),
            (self.provision_state, "provision state"),
            (self.bridge_device_credential, "Bridge device credential"),
            (self.trust_root_certificate, "managed guest trust-root certificate"),
        ):
            _require_existing_regular_file(path, label=label)


def _run_git_capture(
    repo_root: Path,
    argv: Sequence[str],
    *,
    environment: Mapping[str, str],
) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *argv],
        cwd=str(repo_root),
        env=dict(environment),
        check=False,
        capture_output=True,
        text=True,
        timeout=60.0,
    )
    if completed.returncode != 0:
        raise R002FOneShotProductionQualificationError(
            "git checkout authority command failed",
            step="checkout-authority",
            exit_code=int(completed.returncode),
        )
    return str(completed.stdout)


def require_exact_clean_checkout(
    repo_root: Path,
    expected_commit: str,
    *,
    environment: Mapping[str, str],
) -> None:
    expected = canonical_git_sha1(expected_commit)
    actual = _run_git_capture(
        repo_root,
        ["rev-parse", "--verify", "HEAD"],
        environment=environment,
    ).strip()
    if actual != expected:
        raise R002FOneShotProductionQualificationError(
            "qualification checkout HEAD differs from runner_source_commit",
            step="checkout-authority",
        )
    status_text = _run_git_capture(
        repo_root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        environment=environment,
    )
    if status_text:
        raise R002FOneShotProductionQualificationError(
            "qualification checkout is not clean",
            step="checkout-authority",
        )


def _create_run_directory(path: Path) -> Path:
    target = path.expanduser().absolute()
    parent = require_existing_directory(target.parent, label="qualification run parent")
    if target.exists() or target.is_symlink():
        raise FileExistsError("qualification run_dir must not already exist")
    if path_chain_has_redirect(parent) or path_chain_has_redirect(target):
        raise PermissionError("qualification run_dir authority is redirected")
    os.mkdir(target, 0o700)
    try:
        current = target.stat()
        if (
            not stat.S_ISDIR(current.st_mode)
            or not target.is_dir()
            or path_chain_has_redirect(target)
        ):
            raise RuntimeError("qualification run_dir authority changed after create")
    except BaseException:
        try:
            target.rmdir()
        except OSError:
            pass
        raise
    return target


_PYTHON_ENVIRONMENT_KEYS = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONWARNINGS",
        "PYTHONBREAKPOINT",
        "PYTHONUSERBASE",
        "PYTHONSAFEPATH",
    }
)
_ISOLATED_SCRIPT_BOOTSTRAP = (
    "import runpy,sys;"
    "src=sys.argv.pop(1);"
    "script=sys.argv.pop(1);"
    "sys.path.insert(0,src);"
    "sys.argv[0]=script;"
    "runpy.run_path(script,run_name='__main__')"
)


def _child_environment(
    *,
    source: Mapping[str, str],
    repo_root: Path,
) -> dict[str, str]:
    username = source.get(BOOTSTRAP_USERNAME_ENV)
    password = source.get(BOOTSTRAP_PASSWORD_ENV)
    if not isinstance(username, str) or not username.strip():
        raise R002FOneShotProductionQualificationError(
            f"{BOOTSTRAP_USERNAME_ENV} is required",
            step="credential-preflight",
        )
    if not isinstance(password, str) or not password:
        raise R002FOneShotProductionQualificationError(
            f"{BOOTSTRAP_PASSWORD_ENV} is required",
            step="credential-preflight",
        )
    env = {str(key): str(value) for key, value in source.items()}
    for key in _PYTHON_ENVIRONMENT_KEYS:
        env.pop(key, None)
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _proof_digest(path: Path, *, label: str) -> str:
    data = read_file_pinned(
        path,
        max_bytes=_MAX_COMPONENT_PROOF_BYTES,
        label=label,
        allow_empty=False,
    )
    return _canonical_sha256_bytes(data)


def _run_child_step(
    *,
    label: str,
    argv: Sequence[str],
    repo_root: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    command_runner: Callable[..., object],
) -> None:
    completed = command_runner(
        list(argv),
        cwd=str(repo_root),
        env=dict(environment),
        check=False,
        timeout=timeout_seconds,
    )
    returncode = getattr(completed, "returncode", None)
    if (
        not isinstance(returncode, int)
        or isinstance(returncode, bool)
        or returncode != 0
    ):
        raise R002FOneShotProductionQualificationError(
            f"{label} failed",
            step=label,
            exit_code=returncode if isinstance(returncode, int) else None,
        )


def _write_failure_marker(
    run_dir: Path,
    *,
    runner_source_commit: str,
    failure: BaseException,
) -> None:
    marker = run_dir / FAILURE_MARKER_NAME
    if marker.exists() or marker.is_symlink():
        return
    step = getattr(failure, "step", "coordinator")
    exit_code = getattr(failure, "exit_code", None)
    payload: dict[str, object] = {
        "schema_version": _PROOF_SCHEMA_VERSION,
        "qualification": "R002F_ONE_SHOT_PRODUCTION_QUALIFICATION_FAILURE",
        "status": "FAILED_CLOSED",
        "runner_source_commit": runner_source_commit,
        "failed_step": step if isinstance(step, str) and step else "coordinator",
        "error_type": type(failure).__name__,
        "proof_authority": False,
    }
    if isinstance(exit_code, int) and not isinstance(exit_code, bool):
        payload["exit_code"] = exit_code
    try:
        write_json_create_only(
            marker,
            payload,
            max_bytes=_MAX_PROOF_BYTES,
            label="R002F one-shot qualification failure marker",
        )
    except BaseException:
        # Never replace the primary qualification failure with diagnostic failure.
        return


def run_r002f_one_shot_production_qualification(
    request: R002FOneShotProductionQualificationRequest,
    *,
    environment: Mapping[str, str] | None = None,
    python_executable: str | None = None,
    command_runner: Callable[..., object] = subprocess.run,
    administrator_preflight: Callable[[], None] = require_windows_administrator,
    checkout_validator: Callable[..., None] = require_exact_clean_checkout,
    cross_proof_verifier: Callable[..., dict[str, object]] = (
        verify_r002f_production_proof_bundle
    ),
) -> dict[str, object]:
    if not isinstance(request, R002FOneShotProductionQualificationRequest):
        raise TypeError("request must be R002FOneShotProductionQualificationRequest")
    request.validate()

    source_environment = os.environ if environment is None else environment
    safe_environment = _safe_environment_without_bootstrap(source_environment)
    repo_root = request.repo_root.expanduser().absolute()
    checkout_validator(
        repo_root,
        request.runner_source_commit,
        environment=safe_environment,
    )
    administrator_preflight()
    child_environment = _child_environment(
        source=source_environment,
        repo_root=repo_root,
    )

    executable = sys.executable if python_executable is None else python_executable
    executable = _require_nonempty_text(executable, "python_executable")
    scripts_root = repo_root / "scripts"
    script_paths = {
        "managed-hyperv": scripts_root / "qualify_managed_hyperv_agent.py",
        "composite-activation": scripts_root / "qualify_hms_bridge_composite_activation.py",
        "authenticated-agent-transport": (
            scripts_root / "qualify_hms_bridge_composite_agent_transport.py"
        ),
        "openai-control-plane": (
            scripts_root / "qualify_hms_bridge_openai_control_plane_command_flow.py"
        ),
    }
    for label, path in script_paths.items():
        _require_existing_regular_file(path, label=f"{label} qualification script")

    run_dir: Path | None = None
    try:
        run_dir = _create_run_directory(request.run_dir)
        managed_proof = run_dir / MANAGED_HYPERV_PROOF_NAME
        activation_proof = run_dir / COMPOSITE_ACTIVATION_PROOF_NAME
        transport_proof = run_dir / AGENT_TRANSPORT_PROOF_NAME
        openai_proof = run_dir / OPENAI_CONTROL_PLANE_PROOF_NAME
        challenge_file = run_dir / OPENAI_CHALLENGE_NAME
        cross_proof = run_dir / CROSS_PROOF_NAME
        final_manifest = run_dir / FINAL_MANIFEST_NAME

        source_root = str((repo_root / "src").expanduser().absolute())

        def isolated_script_prefix(script_path: Path) -> list[str]:
            return [
                executable,
                "-I",
                "-X",
                "utf8",
                "-c",
                _ISOLATED_SCRIPT_BOOTSTRAP,
                source_root,
                str(script_path),
            ]

        steps: tuple[tuple[str, list[str], Path], ...] = (
            (
                "managed-hyperv",
                [
                    *isolated_script_prefix(script_paths["managed-hyperv"]),
                    "--instance-id",
                    request.instance_id,
                    "--vm-name",
                    request.vm_name,
                    "--package-root",
                    str(request.package_root.expanduser().absolute()),
                    "--package-manifest",
                    str(request.package_manifest.expanduser().absolute()),
                    "--runtime-config",
                    str(request.runtime_config.expanduser().absolute()),
                    "--instance-registry",
                    str(request.instance_registry.expanduser().absolute()),
                    "--provision-state",
                    str(request.provision_state.expanduser().absolute()),
                    "--instance-runtime-dir",
                    str(request.instance_runtime_dir.expanduser().absolute()),
                    "--bridge-device-credential",
                    str(request.bridge_device_credential.expanduser().absolute()),
                    "--proof",
                    str(managed_proof),
                    "--max-reconcile-steps",
                    str(request.max_reconcile_steps),
                ],
                managed_proof,
            ),
            (
                "composite-activation",
                [
                    *isolated_script_prefix(script_paths["composite-activation"]),
                    "--trust-root-certificate",
                    str(request.trust_root_certificate.expanduser().absolute()),
                    "--proof",
                    str(activation_proof),
                ],
                activation_proof,
            ),
            (
                "authenticated-agent-transport",
                [
                    *isolated_script_prefix(script_paths["authenticated-agent-transport"]),
                    "--proof",
                    str(transport_proof),
                ],
                transport_proof,
            ),
            (
                "openai-control-plane",
                [
                    *isolated_script_prefix(script_paths["openai-control-plane"]),
                    "--challenge",
                    str(challenge_file),
                    "--proof",
                    str(openai_proof),
                    "--source-commit",
                    request.challenge_source_commit,
                    "--path",
                    request.challenge_workspace_path,
                    "--expected-sha256",
                    request.challenge_expected_sha256,
                    "--timeout",
                    str(float(request.external_timeout_seconds)),
                ],
                openai_proof,
            ),
        )

        component_digests: dict[str, str] = {}
        for label, argv, proof_path in steps:
            checkout_validator(
                repo_root,
                request.runner_source_commit,
                environment=safe_environment,
            )
            _run_child_step(
                label=label,
                argv=argv,
                repo_root=repo_root,
                environment=child_environment,
                timeout_seconds=float(request.step_timeout_seconds),
                command_runner=command_runner,
            )
            component_digests[label] = _proof_digest(
                proof_path,
                label=f"{label} proof",
            )

        challenge_digest = _proof_digest(
            challenge_file,
            label="OpenAI control-plane challenge",
        )
        checkout_validator(
            repo_root,
            request.runner_source_commit,
            environment=safe_environment,
        )
        cross_result = cross_proof_verifier(
            managed_hyperv_proof_path=managed_proof,
            composite_activation_proof_path=activation_proof,
            agent_transport_proof_path=transport_proof,
            openai_control_plane_proof_path=openai_proof,
            output_proof_path=cross_proof,
        )
        if (
            not isinstance(cross_result, dict)
            or cross_result.get("qualification") != "R002F_PRODUCTION_CROSS_PROOF_GATE"
            or cross_result.get("instance_id") != request.instance_id
            or cross_result.get("source_commit") != request.challenge_source_commit
            or cross_result.get("managed_hyperv_proof_sha256")
            != component_digests["managed-hyperv"]
            or cross_result.get("composite_activation_proof_sha256")
            != component_digests["composite-activation"]
            or cross_result.get("authenticated_agent_transport_proof_sha256")
            != component_digests["authenticated-agent-transport"]
            or cross_result.get("openai_control_plane_proof_sha256")
            != component_digests["openai-control-plane"]
            or cross_result.get("cross_proof_identity_binding_proven") is not True
            or cross_result.get("full_bridge_command_flow_proven") is not False
            or cross_result.get("chatgpt_ui_origin_proven") is not False
        ):
            raise R002FOneShotProductionQualificationError(
                "cross-proof gate returned an invalid proof boundary",
                step="cross-proof",
            )

        cross_digest = _proof_digest(cross_proof, label="R002F cross proof")
        checkout_validator(
            repo_root,
            request.runner_source_commit,
            environment=safe_environment,
        )
        manifest = {
            "schema_version": _PROOF_SCHEMA_VERSION,
            "qualification": "R002F_ONE_SHOT_PRODUCTION_QUALIFICATION",
            "status": "COMPONENT_LIVE_PROOFS_CROSS_BOUND",
            "runner_source_commit": request.runner_source_commit,
            "challenge_source_commit": request.challenge_source_commit,
            "instance_id": cross_result["instance_id"],
            "vm_id": cross_result["vm_id"],
            "device_id": cross_result["device_id"],
            "agent_boot_id": cross_result["agent_boot_id"],
            "tunnel_executable_sha256": cross_result["tunnel_executable_sha256"],
            "managed_hyperv_proof_sha256": component_digests["managed-hyperv"],
            "composite_activation_proof_sha256": component_digests[
                "composite-activation"
            ],
            "authenticated_agent_transport_proof_sha256": component_digests[
                "authenticated-agent-transport"
            ],
            "openai_control_plane_proof_sha256": component_digests[
                "openai-control-plane"
            ],
            "openai_control_plane_challenge_sha256": challenge_digest,
            "cross_proof_sha256": cross_digest,
            "hyperv_guest_proven": True,
            "live_managed_guest_tls_proven": True,
            "authenticated_agent_transport_proven": True,
            "openai_control_plane_origin_proven": True,
            "durable_external_principal_read_proven": True,
            "cross_proof_identity_binding_proven": True,
            "chatgpt_ui_origin_proven": False,
            "token_specific_client_auth_attestation_proven": False,
            "token_endpoint_private_key_jwt_exchange_proven": False,
            "chatgpt_app_oauth_client_proven": False,
            "full_bridge_command_flow_proven": False,
            "bootstrap_retired": False,
            "pairing_ready": False,
            "automatic_start_enabled": False,
        }
        write_json_create_only(
            final_manifest,
            manifest,
            max_bytes=_MAX_PROOF_BYTES,
            label="R002F one-shot production qualification manifest",
        )
        return manifest
    except BaseException as exc:
        if run_dir is not None:
            _write_failure_marker(
                run_dir,
                runner_source_commit=request.runner_source_commit,
                failure=exc,
            )
        raise
