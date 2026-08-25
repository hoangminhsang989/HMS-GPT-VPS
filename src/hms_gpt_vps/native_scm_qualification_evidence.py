from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Mapping

from .agent_package import AgentPackageManifest
from .agent_package_manifest_artifact import (
    canonical_agent_package_manifest_sha256,
    managed_agent_package_manifest_path,
)
from .agent_service_install import AgentServiceConfig
from .agent_service_runtime_config import AgentServiceRuntimeConfig


_INSTALL_RESULT_KEYS = frozenset(
    {
        "ready",
        "service_name",
        "status",
        "start_mode",
        "start_name",
        "agent_root",
        "package_root",
        "package_manifest_path",
        "package_manifest_sha256",
        "package_file_count",
        "package_total_size",
        "binary_path",
        "binary_sha256",
        "runtime_config_path",
        "runtime_config_sha256",
        "runtime_config_changed",
        "service_sid_type",
        "workspace",
        "state_path",
    }
)

_READINESS_RESULT_KEYS = frozenset(
    {
        "service_ready",
        "application_health",
        "service_exists",
        "service_running",
        "local_service_account",
        "binary_command_ok",
        "agent_root_layout_ok",
        "package_manifest_exists",
        "package_manifest_size_ok",
        "package_manifest_sha256_ok",
        "package_manifest_sha256",
        "package_tree_ok",
        "package_file_count",
        "package_total_size",
        "binary_sha256_ok",
        "binary_sha256",
        "runtime_config_exists",
        "runtime_config_sha256_ok",
        "runtime_config_sha256",
        "runtime_config_read",
        "service_sid_unrestricted",
        "agent_root_read_execute",
        "workspace_modify",
        "state_modify",
    }
)

_READINESS_TRUE_KEYS = frozenset(
    {
        "service_ready",
        "service_exists",
        "service_running",
        "local_service_account",
        "binary_command_ok",
        "agent_root_layout_ok",
        "package_manifest_exists",
        "package_manifest_size_ok",
        "package_manifest_sha256_ok",
        "package_tree_ok",
        "binary_sha256_ok",
        "runtime_config_exists",
        "runtime_config_sha256_ok",
        "runtime_config_read",
        "service_sid_unrestricted",
        "agent_root_read_execute",
        "workspace_modify",
        "state_modify",
    }
)

_NATIVE_PROOF_KEYS = frozenset(
    {
        "schema_version",
        "qualification",
        "package",
        "install",
        "readiness",
        "first_health",
        "first_listener",
        "first_epoch",
        "reconnect_epoch",
        "second_health",
        "second_listener",
        "post_restart_epoch",
        "transport_target",
        "full_bridge_command_flow_proven",
        "hyperv_guest_proven",
        "cleanup_verified",
    }
)


def _require_object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise RuntimeError(f"{label} keys must be strings")
    return value


def _require_exact_keys(
    value: Mapping[str, object], expected: frozenset[str], label: str
) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RuntimeError(f"{label} schema mismatch: missing={missing} extra={extra}")


def require_bool_evidence(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise RuntimeError(f"{label} must be a JSON boolean")
    return value


def require_true_evidence(value: object, label: str) -> bool:
    result = require_bool_evidence(value, label)
    if result is not True:
        raise RuntimeError(f"{label} must be true")
    return result


def require_false_evidence(value: object, label: str) -> bool:
    result = require_bool_evidence(value, label)
    if result is not False:
        raise RuntimeError(f"{label} must be false")
    return result


def require_int_evidence(
    value: object,
    label: str,
    *,
    minimum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"{label} must be a JSON integer")
    if minimum is not None and value < minimum:
        raise RuntimeError(f"{label} must be >= {minimum}")
    return value


def require_string_evidence(
    value: object,
    label: str,
    *,
    nonempty: bool = True,
) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"{label} must be a JSON string")
    if nonempty and not value:
        raise RuntimeError(f"{label} must be non-empty")
    return value


def require_sha256_evidence(value: object, label: str) -> str:
    text = require_string_evidence(value, label)
    if len(text) != 64 or text != text.lower():
        raise RuntimeError(f"{label} must be canonical lowercase SHA-256")
    if any(char not in "0123456789abcdef" for char in text):
        raise RuntimeError(f"{label} must be canonical lowercase SHA-256")
    return text


def _same_windows_path(left: str, right: str) -> bool:
    return str(PureWindowsPath(left)).casefold() == str(PureWindowsPath(right)).casefold()


def _require_windows_path(value: object, expected: str, label: str) -> str:
    text = require_string_evidence(value, label)
    if not PureWindowsPath(text).is_absolute():
        raise RuntimeError(f"{label} must be an absolute Windows path")
    if not _same_windows_path(text, expected):
        raise RuntimeError(f"{label} differs from managed authority")
    return text


def validate_service_exists_result(result: object) -> bool:
    payload = _require_object(result, "service-exists evidence")
    _require_exact_keys(payload, frozenset({"exists"}), "service-exists evidence")
    return require_bool_evidence(payload["exists"], "service-exists evidence exists")


def validate_single_true_result(result: object, key: str, label: str) -> None:
    payload = _require_object(result, label)
    _require_exact_keys(payload, frozenset({key}), label)
    require_true_evidence(payload[key], f"{label} {key}")


def validate_listener_result(result: object, *, service_name: str) -> dict[str, object]:
    label = "native listener evidence"
    payload = _require_object(result, label)
    _require_exact_keys(
        payload,
        frozenset({"service_name", "process_id", "listener_count", "local_addresses"}),
        label,
    )
    actual_service = require_string_evidence(payload["service_name"], f"{label} service_name")
    if actual_service != service_name:
        raise RuntimeError("native listener service_name mismatch")
    process_id = require_int_evidence(payload["process_id"], f"{label} process_id", minimum=1)
    listener_count = require_int_evidence(
        payload["listener_count"], f"{label} listener_count", minimum=0
    )
    addresses_value = payload["local_addresses"]
    if not isinstance(addresses_value, list):
        raise RuntimeError("native listener local_addresses must be a JSON array")
    addresses: list[str] = []
    for index, value in enumerate(addresses_value):
        addresses.append(
            require_string_evidence(value, f"{label} local_addresses[{index}]")
        )
    if listener_count != 1:
        raise RuntimeError("Agent health must have exactly one listening socket")
    if addresses != ["127.0.0.1"]:
        raise RuntimeError("Agent health listener is not bound exclusively to IPv4 loopback")
    return {
        "service_name": actual_service,
        "process_id": process_id,
        "listener_count": listener_count,
        "local_addresses": addresses,
    }


def validate_install_result(
    result: object,
    *,
    service: AgentServiceConfig,
    manifest: AgentPackageManifest,
    runtime: AgentServiceRuntimeConfig,
) -> dict[str, object]:
    label = "native installer evidence"
    payload = _require_object(result, label)
    _require_exact_keys(payload, _INSTALL_RESULT_KEYS, label)

    ready = require_true_evidence(payload["ready"], f"{label} ready")
    service_name = require_string_evidence(payload["service_name"], f"{label} service_name")
    if service_name != service.service_name:
        raise RuntimeError("native installer service_name mismatch")
    status = require_string_evidence(payload["status"], f"{label} status")
    if status != "Running":
        raise RuntimeError("native installer service status mismatch")
    start_mode = require_string_evidence(payload["start_mode"], f"{label} start_mode")
    if start_mode != "Auto":
        raise RuntimeError("native installer service start mode mismatch")
    start_name = require_string_evidence(payload["start_name"], f"{label} start_name")
    if start_name != r"NT AUTHORITY\LocalService":
        raise RuntimeError("native installer service account mismatch")

    agent_root = _require_windows_path(payload["agent_root"], service.agent_root_path, f"{label} agent_root")
    package_root = _require_windows_path(payload["package_root"], service.package_path, f"{label} package_root")
    package_manifest_path = _require_windows_path(
        payload["package_manifest_path"],
        managed_agent_package_manifest_path(service.agent_root_path),
        f"{label} package_manifest_path",
    )
    package_manifest_sha256 = require_sha256_evidence(
        payload["package_manifest_sha256"], f"{label} package_manifest_sha256"
    )
    if package_manifest_sha256 != canonical_agent_package_manifest_sha256(manifest):
        raise RuntimeError("native installer package manifest SHA-256 mismatch")
    package_file_count = require_int_evidence(
        payload["package_file_count"], f"{label} package_file_count", minimum=1
    )
    if package_file_count != manifest.file_count:
        raise RuntimeError("native installer package file-count proof mismatch")
    package_total_size = require_int_evidence(
        payload["package_total_size"], f"{label} package_total_size", minimum=1
    )
    if package_total_size != manifest.total_size:
        raise RuntimeError("native installer package size proof mismatch")

    binary_path = _require_windows_path(payload["binary_path"], service.binary_path, f"{label} binary_path")
    binary_sha256 = require_sha256_evidence(payload["binary_sha256"], f"{label} binary_sha256")
    if binary_sha256 != manifest.sha256:
        raise RuntimeError("native installer entrypoint SHA-256 mismatch")
    runtime_config_path = _require_windows_path(
        payload["runtime_config_path"], service.runtime_config_path, f"{label} runtime_config_path"
    )
    runtime_config_sha256 = require_sha256_evidence(
        payload["runtime_config_sha256"], f"{label} runtime_config_sha256"
    )
    if runtime_config_sha256 != runtime.sha256():
        raise RuntimeError("native installer runtime config SHA-256 mismatch")
    runtime_config_changed = require_bool_evidence(
        payload["runtime_config_changed"], f"{label} runtime_config_changed"
    )
    service_sid_type = require_string_evidence(
        payload["service_sid_type"], f"{label} service_sid_type"
    )
    if service_sid_type != "UNRESTRICTED":
        raise RuntimeError("native installer service SID type mismatch")
    workspace = _require_windows_path(payload["workspace"], service.workspace_path, f"{label} workspace")
    state_path = _require_windows_path(payload["state_path"], service.state_path, f"{label} state_path")

    return {
        "ready": ready,
        "service_name": service_name,
        "status": status,
        "start_mode": start_mode,
        "start_name": start_name,
        "agent_root": agent_root,
        "package_root": package_root,
        "package_manifest_path": package_manifest_path,
        "package_manifest_sha256": package_manifest_sha256,
        "package_file_count": package_file_count,
        "package_total_size": package_total_size,
        "binary_path": binary_path,
        "binary_sha256": binary_sha256,
        "runtime_config_path": runtime_config_path,
        "runtime_config_sha256": runtime_config_sha256,
        "runtime_config_changed": runtime_config_changed,
        "service_sid_type": service_sid_type,
        "workspace": workspace,
        "state_path": state_path,
    }


def validate_readiness_result(
    result: object,
    *,
    manifest: AgentPackageManifest,
    runtime: AgentServiceRuntimeConfig,
) -> dict[str, object]:
    label = "native readiness evidence"
    payload = _require_object(result, label)
    _require_exact_keys(payload, _READINESS_RESULT_KEYS, label)

    validated: dict[str, object] = {}
    for key in sorted(_READINESS_TRUE_KEYS):
        validated[key] = require_true_evidence(payload[key], f"{label} {key}")

    application_health = require_string_evidence(
        payload["application_health"], f"{label} application_health"
    )
    if application_health != "NOT_IMPLEMENTED":
        raise RuntimeError("native readiness application health marker mismatch")
    validated["application_health"] = application_health

    package_manifest_sha256 = require_sha256_evidence(
        payload["package_manifest_sha256"], f"{label} package_manifest_sha256"
    )
    if package_manifest_sha256 != canonical_agent_package_manifest_sha256(manifest):
        raise RuntimeError("native readiness package manifest SHA-256 mismatch")
    validated["package_manifest_sha256"] = package_manifest_sha256

    package_file_count = require_int_evidence(
        payload["package_file_count"], f"{label} package_file_count", minimum=1
    )
    if package_file_count != manifest.file_count:
        raise RuntimeError("native readiness package file-count proof mismatch")
    validated["package_file_count"] = package_file_count

    package_total_size = require_int_evidence(
        payload["package_total_size"], f"{label} package_total_size", minimum=1
    )
    if package_total_size != manifest.total_size:
        raise RuntimeError("native readiness package size proof mismatch")
    validated["package_total_size"] = package_total_size

    binary_sha256 = require_sha256_evidence(payload["binary_sha256"], f"{label} binary_sha256")
    if binary_sha256 != manifest.sha256:
        raise RuntimeError("native readiness entrypoint SHA-256 mismatch")
    validated["binary_sha256"] = binary_sha256

    runtime_config_sha256 = require_sha256_evidence(
        payload["runtime_config_sha256"], f"{label} runtime_config_sha256"
    )
    if runtime_config_sha256 != runtime.sha256():
        raise RuntimeError("native readiness runtime config SHA-256 mismatch")
    validated["runtime_config_sha256"] = runtime_config_sha256
    return validated


def validate_native_scm_proof(proof: object) -> dict[str, object]:
    label = "native SCM proof"
    payload = _require_object(proof, label)
    _require_exact_keys(payload, _NATIVE_PROOF_KEYS, label)
    if require_int_evidence(payload["schema_version"], f"{label} schema_version") != 1:
        raise RuntimeError("native SCM proof schema version mismatch")
    if require_string_evidence(payload["qualification"], f"{label} qualification") != "native_windows_scm_packaged_agent":
        raise RuntimeError("native SCM proof qualification mismatch")

    package = _require_object(payload["package"], f"{label} package")
    _require_exact_keys(
        package,
        frozenset({"schema_version", "platform", "version", "entrypoint", "file_count", "total_size", "entrypoint_sha256"}),
        f"{label} package",
    )
    if require_int_evidence(package["schema_version"], "native SCM package schema_version") != 2:
        raise RuntimeError("native SCM package schema mismatch")
    if require_string_evidence(package["platform"], "native SCM package platform") != "windows-x64":
        raise RuntimeError("native SCM package platform mismatch")
    require_string_evidence(package["version"], "native SCM package version")
    if require_string_evidence(package["entrypoint"], "native SCM package entrypoint") != "hms-agent.exe":
        raise RuntimeError("native SCM package entrypoint mismatch")
    package_file_count = require_int_evidence(package["file_count"], "native SCM package file_count", minimum=1)
    package_total_size = require_int_evidence(package["total_size"], "native SCM package total_size", minimum=1)
    package_sha256 = require_sha256_evidence(package["entrypoint_sha256"], "native SCM package entrypoint_sha256")

    install = _require_object(payload["install"], f"{label} install")
    _require_exact_keys(
        install,
        frozenset({"ready", "start_name", "service_sid_type", "package_file_count", "package_total_size", "binary_sha256", "runtime_config_sha256"}),
        f"{label} install",
    )
    require_true_evidence(install["ready"], "native SCM install ready")
    if require_string_evidence(install["start_name"], "native SCM install start_name") != r"NT AUTHORITY\LocalService":
        raise RuntimeError("native SCM install account mismatch")
    if require_string_evidence(install["service_sid_type"], "native SCM install service_sid_type") != "UNRESTRICTED":
        raise RuntimeError("native SCM install SID type mismatch")
    if require_int_evidence(install["package_file_count"], "native SCM install package_file_count", minimum=1) != package_file_count:
        raise RuntimeError("native SCM install/package file-count mismatch")
    if require_int_evidence(install["package_total_size"], "native SCM install package_total_size", minimum=1) != package_total_size:
        raise RuntimeError("native SCM install/package size mismatch")
    if require_sha256_evidence(install["binary_sha256"], "native SCM install binary_sha256") != package_sha256:
        raise RuntimeError("native SCM install/package entrypoint SHA-256 mismatch")
    require_sha256_evidence(install["runtime_config_sha256"], "native SCM install runtime_config_sha256")

    readiness = _require_object(payload["readiness"], f"{label} readiness")
    _require_exact_keys(
        readiness,
        frozenset({"service_ready", "local_service_account", "service_sid_unrestricted", "package_tree_ok", "package_file_count", "package_total_size", "runtime_config_sha256_ok"}),
        f"{label} readiness",
    )
    for key in ("service_ready", "local_service_account", "service_sid_unrestricted", "package_tree_ok", "runtime_config_sha256_ok"):
        require_true_evidence(readiness[key], f"native SCM readiness {key}")
    if require_int_evidence(readiness["package_file_count"], "native SCM readiness package_file_count", minimum=1) != package_file_count:
        raise RuntimeError("native SCM readiness/package file-count mismatch")
    if require_int_evidence(readiness["package_total_size"], "native SCM readiness package_total_size", minimum=1) != package_total_size:
        raise RuntimeError("native SCM readiness/package size mismatch")

    first_listener = validate_listener_result(payload["first_listener"], service_name="HMSAgent")
    second_listener = validate_listener_result(payload["second_listener"], service_name="HMSAgent")
    if second_listener["process_id"] == first_listener["process_id"]:
        raise RuntimeError("native SCM listener process id did not change across restart")

    first_epoch = require_int_evidence(payload["first_epoch"], "native SCM first_epoch", minimum=1)
    reconnect_epoch = require_int_evidence(payload["reconnect_epoch"], "native SCM reconnect_epoch", minimum=1)
    post_restart_epoch = require_int_evidence(payload["post_restart_epoch"], "native SCM post_restart_epoch", minimum=1)
    if not first_epoch < reconnect_epoch < post_restart_epoch:
        raise RuntimeError("native SCM epoch ordering mismatch")

    for key in ("first_health", "second_health"):
        health = _require_object(payload[key], f"native SCM {key}")
        if key == "first_health":
            expected = frozenset({"instance_id", "agent_version", "service_identity", "privilege", "listener_scope", "boot_id"})
        else:
            expected = frozenset({"boot_id", "service_identity", "privilege", "listener_scope"})
        _require_exact_keys(health, expected, f"native SCM {key}")
        for health_key in expected:
            require_string_evidence(health[health_key], f"native SCM {key} {health_key}")
    if payload["first_health"]["boot_id"] == payload["second_health"]["boot_id"]:  # type: ignore[index]
        raise RuntimeError("native SCM boot id did not change across restart")

    if require_string_evidence(payload["transport_target"], "native SCM transport_target") != "loopback-closed-port-retry-only":
        raise RuntimeError("native SCM transport target mismatch")
    require_false_evidence(payload["full_bridge_command_flow_proven"], "native SCM full_bridge_command_flow_proven")
    require_false_evidence(payload["hyperv_guest_proven"], "native SCM hyperv_guest_proven")
    require_true_evidence(payload["cleanup_verified"], "native SCM cleanup_verified")
    return dict(payload)
