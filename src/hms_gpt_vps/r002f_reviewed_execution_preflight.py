from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sys
from typing import Callable, Mapping

from .external_mcp_command_flow_contract import canonical_git_sha1
from .r002f_execution_preflight import (
    R002FExecutionPreflightRequest,
    run_r002f_execution_preflight,
)
from .r002f_reviewed_checkout_authority import (
    R002FReviewedCheckoutAuthorityError,
    require_reviewed_clean_checkout,
)
from .r002f_reviewed_git_environment import (
    checkout_validation_environment,
    sanitize_git_control_environment,
)
from .r002f_reviewed_preflight_proof import (
    component_digest,
    component_path_for,
    publish_reviewed_preflight_proof,
    render_reviewed_command,
    reviewed_one_shot_argv,
    validate_final_proof_path,
)
from .r002f_reviewed_toolchain_authority import canonical_sha256

_SCHEMA_VERSION = 2


class R002FReviewedExecutionPreflightError(RuntimeError):
    pass


def _require_component_shape(component: dict[str, object]) -> None:
    if component.get("qualification") != "R002F_ZERO_MANUAL_EXECUTION_PREFLIGHT":
        raise R002FReviewedExecutionPreflightError(
            "component execution preflight qualification differs"
        )
    if not isinstance(component.get("ready"), bool):
        raise R002FReviewedExecutionPreflightError(
            "component execution preflight ready flag is invalid"
        )


def run_r002f_reviewed_execution_preflight(
    request: R002FExecutionPreflightRequest,
    *,
    expected_runner_source_commit: str,
    final_proof_path: Path,
    git_executable: Path,
    git_executable_sha256: str,
    python_executable: Path | None = None,
    environment: Mapping[str, str] | None = None,
    checkout_validator: Callable[..., None] = require_reviewed_clean_checkout,
    component_runner: Callable[..., dict[str, object]] = run_r002f_execution_preflight,
) -> dict[str, object]:
    """Cross-bind the component preflight to reviewed commit + Git binary authority."""

    if not isinstance(request, R002FExecutionPreflightRequest):
        raise TypeError("request must be R002FExecutionPreflightRequest")
    request.validate_shape()
    expected = canonical_git_sha1(expected_runner_source_commit)
    git_sha = canonical_sha256(
        git_executable_sha256,
        "reviewed Git executable SHA-256",
    )
    git_path = git_executable.expanduser().absolute()
    python_path = (
        Path(sys.executable).expanduser().absolute()
        if python_executable is None
        else python_executable.expanduser().absolute()
    )
    final_path = validate_final_proof_path(final_proof_path, request.repo_root)
    component_path = component_path_for(final_path)
    if component_path.exists() or component_path.is_symlink():
        raise FileExistsError("component execution preflight proof path must be new")

    source_environment = os.environ if environment is None else environment
    safe_environment = sanitize_git_control_environment(source_environment)
    checkout_validator(
        request.repo_root.expanduser().absolute(),
        expected,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=safe_environment,
    )

    component = component_runner(
        replace(request, proof_path=component_path),
        environment=safe_environment,
    )
    if not isinstance(component, dict):
        raise R002FReviewedExecutionPreflightError(
            "component execution preflight result is not an object"
        )
    _require_component_shape(component)

    checkout_validator(
        request.repo_root.expanduser().absolute(),
        expected,
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment=safe_environment,
    )
    component_sha256 = component_digest(component_path)
    component_runner_commit = component.get("runner_source_commit")
    if component_runner_commit is not None and component_runner_commit != expected:
        raise R002FReviewedExecutionPreflightError(
            "component execution preflight self-reported a different runner commit"
        )

    ready = component.get("ready") is True
    one_shot_argv: list[str] | None = None
    one_shot_powershell: str | None = None
    if ready:
        if component_runner_commit != expected:
            raise R002FReviewedExecutionPreflightError(
                "ready component execution preflight lacks reviewed runner commit binding"
            )
        one_shot_argv = reviewed_one_shot_argv(
            component.get("one_shot_argv"),
            expected_commit=expected,
            repo_root=request.repo_root,
            python_executable=python_path,
            git_executable=git_path,
            git_executable_sha256=git_sha,
        )
        one_shot_powershell = render_reviewed_command(one_shot_argv)

    proof = {
        "schema_version": _SCHEMA_VERSION,
        "qualification": "R002F_REVIEWED_EXECUTION_PREFLIGHT",
        "status": (
            "READY_FOR_REVIEWED_ONE_SHOT_EXECUTION"
            if ready
            else str(component.get("status", "BLOCKED_COMPONENT_PREFLIGHT"))
        ),
        "ready": ready,
        "reviewed_runner_source_commit": expected,
        "runner_source_commit": component_runner_commit,
        "reviewed_checkout_proven": True,
        "git_control_environment_sanitized": True,
        "reviewed_git_executable_path": str(git_path),
        "reviewed_git_executable_sha256": git_sha,
        "reviewed_git_executable_pinned_for_checkout": True,
        "python_executable_path": str(python_path),
        "python_isolated_bootstrap_required": True,
        "component_preflight_path": str(component_path),
        "component_preflight_sha256": component_sha256,
        "component_preflight_authority": False,
        "component_status": component.get("status"),
        "missing_authority": component.get("missing_authority", []),
        "host_blockers": component.get("host_blockers", []),
        "authority_blockers": component.get("authority_blockers", []),
        "derived": component.get("derived", {}),
        "bootstrap_secret_environment_absent": component.get(
            "bootstrap_secret_environment_absent"
        ),
        "bootstrap_environment_required_at_execution": True,
        "bootstrap_environment_names": component.get("bootstrap_environment_names", []),
        "one_shot_argv": one_shot_argv,
        "one_shot_powershell": one_shot_powershell,
        "execution_started": False,
        "hyperv_mutated": False,
        "bridge_started": False,
        "tunnel_started": False,
    }
    publish_reviewed_preflight_proof(final_path, proof)
    return proof


__all__ = [
    "R002FReviewedCheckoutAuthorityError",
    "R002FReviewedExecutionPreflightError",
    "checkout_validation_environment",
    "require_reviewed_clean_checkout",
    "run_r002f_reviewed_execution_preflight",
    "sanitize_git_control_environment",
]
