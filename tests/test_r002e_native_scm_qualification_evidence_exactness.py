from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_package import build_agent_package_manifest
from hms_gpt_vps.agent_package_manifest_artifact import (
    canonical_agent_package_manifest_sha256,
    managed_agent_package_manifest_path,
)
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.native_scm_qualification_evidence import (
    validate_install_result,
    validate_listener_result,
    validate_native_scm_proof,
    validate_readiness_result,
    validate_service_exists_result,
    validate_single_true_result,
)


def _authority(tmp_path: Path):  # type: ignore[no-untyped-def]
    package = tmp_path / "package"
    package.mkdir()
    (package / "hms-agent.exe").write_bytes(b"native-agent-entrypoint")
    manifest = build_agent_package_manifest(package, version="0.1.0")
    service = AgentServiceConfig()
    runtime = AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="ci-native-scm",
        project_id="ci-native-project",
        bridge_origin="https://127.0.0.1:9",
        workspace_root=service.workspace_path,
        state_root=service.state_path,
        python_executable=r"C:\Python\python.exe",
        git_executable=r"C:\Program Files\Git\cmd\git.exe",
        health_port=18765,
    )
    runtime.validate()
    return service, manifest, runtime


def _install_payload(service, manifest, runtime):  # type: ignore[no-untyped-def]
    return {
        "ready": True,
        "service_name": service.service_name,
        "status": "Running",
        "start_mode": "Auto",
        "start_name": r"NT AUTHORITY\LocalService",
        "agent_root": service.agent_root_path,
        "package_root": service.package_path,
        "package_manifest_path": managed_agent_package_manifest_path(service.agent_root_path),
        "package_manifest_sha256": canonical_agent_package_manifest_sha256(manifest),
        "package_file_count": manifest.file_count,
        "package_total_size": manifest.total_size,
        "binary_path": service.binary_path,
        "binary_sha256": manifest.sha256,
        "runtime_config_path": service.runtime_config_path,
        "runtime_config_sha256": runtime.sha256(),
        "runtime_config_changed": True,
        "service_sid_type": "UNRESTRICTED",
        "workspace": service.workspace_path,
        "state_path": service.state_path,
    }


def _readiness_payload(manifest, runtime):  # type: ignore[no-untyped-def]
    payload = {
        "service_ready": True,
        "application_health": "NOT_IMPLEMENTED",
        "service_exists": True,
        "service_running": True,
        "local_service_account": True,
        "binary_command_ok": True,
        "agent_root_layout_ok": True,
        "package_manifest_exists": True,
        "package_manifest_size_ok": True,
        "package_manifest_sha256_ok": True,
        "package_manifest_sha256": canonical_agent_package_manifest_sha256(manifest),
        "package_tree_ok": True,
        "package_file_count": manifest.file_count,
        "package_total_size": manifest.total_size,
        "binary_sha256_ok": True,
        "binary_sha256": manifest.sha256,
        "runtime_config_exists": True,
        "runtime_config_sha256_ok": True,
        "runtime_config_sha256": runtime.sha256(),
        "runtime_config_read": True,
        "service_sid_unrestricted": True,
        "agent_root_read_execute": True,
        "workspace_modify": True,
        "state_modify": True,
    }
    return payload


def _proof(service, manifest, runtime):  # type: ignore[no-untyped-def]
    return {
        "schema_version": 1,
        "qualification": "native_windows_scm_packaged_agent",
        "package": {
            "schema_version": 2,
            "platform": manifest.platform,
            "version": manifest.version,
            "entrypoint": manifest.entrypoint,
            "file_count": manifest.file_count,
            "total_size": manifest.total_size,
            "entrypoint_sha256": manifest.sha256,
        },
        "install": {
            "ready": True,
            "start_name": r"NT AUTHORITY\LocalService",
            "service_sid_type": "UNRESTRICTED",
            "package_file_count": manifest.file_count,
            "package_total_size": manifest.total_size,
            "binary_sha256": manifest.sha256,
            "runtime_config_sha256": runtime.sha256(),
        },
        "readiness": {
            "service_ready": True,
            "local_service_account": True,
            "service_sid_unrestricted": True,
            "package_tree_ok": True,
            "package_file_count": manifest.file_count,
            "package_total_size": manifest.total_size,
            "runtime_config_sha256_ok": True,
        },
        "first_health": {
            "instance_id": "ci-native-scm",
            "agent_version": manifest.version,
            "service_identity": r"NT SERVICE\HMSAgent",
            "privilege": "non-admin",
            "listener_scope": "loopback-only",
            "boot_id": "boot-1",
        },
        "first_listener": {
            "service_name": service.service_name,
            "process_id": 1001,
            "listener_count": 1,
            "local_addresses": ["127.0.0.1"],
        },
        "first_epoch": 1,
        "reconnect_epoch": 2,
        "second_health": {
            "boot_id": "boot-2",
            "service_identity": r"NT SERVICE\HMSAgent",
            "privilege": "non-admin",
            "listener_scope": "loopback-only",
        },
        "second_listener": {
            "service_name": service.service_name,
            "process_id": 1002,
            "listener_count": 1,
            "local_addresses": ["127.0.0.1"],
        },
        "post_restart_epoch": 3,
        "transport_target": "loopback-closed-port-retry-only",
        "full_bridge_command_flow_proven": False,
        "hyperv_guest_proven": False,
        "cleanup_verified": True,
    }


def test_service_exists_rejects_truthy_string() -> None:
    with pytest.raises(RuntimeError, match="JSON boolean"):
        validate_service_exists_result({"exists": "false"})


def test_single_true_result_rejects_string_and_schema_drift() -> None:
    with pytest.raises(RuntimeError, match="JSON boolean"):
        validate_single_true_result({"stopped": "true"}, "stopped", "stop")
    with pytest.raises(RuntimeError, match="schema mismatch"):
        validate_single_true_result({"stopped": True, "extra": False}, "stopped", "stop")


def test_listener_rejects_scalar_address_and_boolean_integer() -> None:
    with pytest.raises(RuntimeError, match="JSON array"):
        validate_listener_result(
            {
                "service_name": "HMSAgent",
                "process_id": 100,
                "listener_count": 1,
                "local_addresses": "127.0.0.1",
            },
            service_name="HMSAgent",
        )
    with pytest.raises(RuntimeError, match="JSON integer"):
        validate_listener_result(
            {
                "service_name": "HMSAgent",
                "process_id": True,
                "listener_count": 1,
                "local_addresses": ["127.0.0.1"],
            },
            service_name="HMSAgent",
        )


def test_listener_rejects_coerced_array_element() -> None:
    with pytest.raises(RuntimeError, match=r"local_addresses\[0\].*JSON string"):
        validate_listener_result(
            {
                "service_name": "HMSAgent",
                "process_id": 100,
                "listener_count": 1,
                "local_addresses": [127001],
            },
            service_name="HMSAgent",
        )


def test_install_result_rejects_truthy_ready_and_string_count(tmp_path: Path) -> None:
    service, manifest, runtime = _authority(tmp_path)
    payload = _install_payload(service, manifest, runtime)
    payload["ready"] = "false"
    with pytest.raises(RuntimeError, match="ready.*JSON boolean"):
        validate_install_result(payload, service=service, manifest=manifest, runtime=runtime)

    payload = _install_payload(service, manifest, runtime)
    payload["package_file_count"] = str(manifest.file_count)
    with pytest.raises(RuntimeError, match="package_file_count.*JSON integer"):
        validate_install_result(payload, service=service, manifest=manifest, runtime=runtime)


def test_install_result_rejects_bool_as_integer_and_unknown_key(tmp_path: Path) -> None:
    service, manifest, runtime = _authority(tmp_path)
    payload = _install_payload(service, manifest, runtime)
    payload["package_total_size"] = True
    with pytest.raises(RuntimeError, match="package_total_size.*JSON integer"):
        validate_install_result(payload, service=service, manifest=manifest, runtime=runtime)

    payload = _install_payload(service, manifest, runtime)
    payload["unexpected"] = True
    with pytest.raises(RuntimeError, match="schema mismatch"):
        validate_install_result(payload, service=service, manifest=manifest, runtime=runtime)


def test_install_result_accepts_exact_evidence(tmp_path: Path) -> None:
    service, manifest, runtime = _authority(tmp_path)
    validated = validate_install_result(
        _install_payload(service, manifest, runtime),
        service=service,
        manifest=manifest,
        runtime=runtime,
    )
    assert validated["ready"] is True
    assert validated["package_file_count"] == manifest.file_count


def test_readiness_rejects_truthy_component_and_string_size(tmp_path: Path) -> None:
    _service, manifest, runtime = _authority(tmp_path)
    payload = _readiness_payload(manifest, runtime)
    payload["package_tree_ok"] = "false"
    with pytest.raises(RuntimeError, match="package_tree_ok.*JSON boolean"):
        validate_readiness_result(payload, manifest=manifest, runtime=runtime)

    payload = _readiness_payload(manifest, runtime)
    payload["package_total_size"] = str(manifest.total_size)
    with pytest.raises(RuntimeError, match="package_total_size.*JSON integer"):
        validate_readiness_result(payload, manifest=manifest, runtime=runtime)


def test_readiness_requires_all_component_evidence_true(tmp_path: Path) -> None:
    _service, manifest, runtime = _authority(tmp_path)
    payload = _readiness_payload(manifest, runtime)
    payload["runtime_config_read"] = False
    with pytest.raises(RuntimeError, match="runtime_config_read.*must be true"):
        validate_readiness_result(payload, manifest=manifest, runtime=runtime)


def test_native_proof_rejects_coerced_boundaries(tmp_path: Path) -> None:
    service, manifest, runtime = _authority(tmp_path)
    proof = _proof(service, manifest, runtime)
    proof["cleanup_verified"] = "true"
    with pytest.raises(RuntimeError, match="cleanup_verified.*JSON boolean"):
        validate_native_scm_proof(proof)

    proof = _proof(service, manifest, runtime)
    proof["full_bridge_command_flow_proven"] = 0
    with pytest.raises(RuntimeError, match="full_bridge_command_flow_proven.*JSON boolean"):
        validate_native_scm_proof(proof)


def test_native_proof_rejects_string_epoch_and_accepts_exact(tmp_path: Path) -> None:
    service, manifest, runtime = _authority(tmp_path)
    proof = _proof(service, manifest, runtime)
    proof["reconnect_epoch"] = "2"
    with pytest.raises(RuntimeError, match="reconnect_epoch.*JSON integer"):
        validate_native_scm_proof(proof)

    exact = _proof(service, manifest, runtime)
    assert validate_native_scm_proof(exact)["cleanup_verified"] is True
