from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from hms_gpt_vps.agent_device_credential_store import GUEST_PROTECTION_SCOPE
from hms_gpt_vps.agent_health_contract import DEFAULT_REQUIRED_CAPABILITIES
from hms_gpt_vps.agent_package import build_agent_package_manifest, write_agent_package_manifest
from hms_gpt_vps.managed_hyperv_agent_qualification import (
    MANAGED_HYPERV_AGENT_QUALIFICATION_NAME,
    MANAGED_HYPERV_AGENT_QUALIFICATION_SCHEMA_VERSION,
    ManagedHyperVAgentQualificationError,
    ManagedHyperVAgentQualificationProof,
    _final_health,
    _load_host_package_authority,
)
from hms_gpt_vps.provision_state import ProvisionState


VM_ID = "11111111-2222-3333-4444-555555555555"


def _proof(**overrides: object) -> ManagedHyperVAgentQualificationProof:
    values: dict[str, object] = {
        "schema_version": MANAGED_HYPERV_AGENT_QUALIFICATION_SCHEMA_VERSION,
        "qualification": MANAGED_HYPERV_AGENT_QUALIFICATION_NAME,
        "instance_id": "hms-01",
        "vm_name": "HMS-GPT-VPS-01",
        "vm_id": VM_ID,
        "device_id": "device-01",
        "device_enrollment_ready": True,
        "device_protection_scope": GUEST_PROTECTION_SCOPE,
        "starting_state": ProvisionState.AGENT_SERVICE_READY.value,
        "final_state": ProvisionState.AGENT_HEALTHY.value,
        "actions": ("AGENT_APPLICATION_HEALTH_VERIFIED",),
        "package_schema_version": 2,
        "package_version": "0.1.0",
        "package_file_count": 1,
        "package_total_size": 20,
        "package_entrypoint_sha256": "a" * 64,
        "package_manifest_sha256": "b" * 64,
        "package_tree_ok": True,
        "package_manifest_sha256_ok": True,
        "local_service_account": True,
        "service_sid_unrestricted": True,
        "runtime_config_sha256_ok": True,
        "service_ready": True,
        "health_status": "ok",
        "health_agent_version": "0.1.0",
        "health_service_identity": r"NT SERVICE\HMSAgent",
        "health_listener_scope": "loopback-only",
        "health_privilege": "non-admin",
        "health_boot_id": "boot-01",
        "health_capabilities": tuple(sorted(DEFAULT_REQUIRED_CAPABILITIES)),
        "hyperv_guest_proven": True,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
    }
    values.update(overrides)
    return ManagedHyperVAgentQualificationProof(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"schema_version": True}, "schema mismatch"),
        ({"device_enrollment_ready": "true"}, "device enrollment"),
        ({"package_file_count": True}, "file-count"),
        ({"package_total_size": True}, "size proof"),
        ({"package_tree_ok": "true"}, "package readiness"),
        ({"hyperv_guest_proven": "true"}, "guest path"),
        ({"full_bridge_command_flow_proven": 0}, "Bridge command flow"),
        ({"package_entrypoint_sha256": "A" * 64}, "entrypoint SHA-256"),
        ({"health_capabilities": ("fs.read",)}, "capabilities"),
    ],
)
def test_qualification_proof_rejects_coerced_or_noncanonical_fields(
    overrides: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        _proof(**overrides).validate()


def test_final_health_rejects_truthy_non_boolean_service_ready() -> None:
    with pytest.raises(
        ManagedHyperVAgentQualificationError,
        match="service readiness",
    ):
        _final_health(
            SimpleNamespace(
                service_ready="true",
                agent_healthy=True,
                health=None,
            )
        )


def test_host_package_authority_rejects_redirect_after_config_capture(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "package-authority"
    package = authority / "hms-agent"
    package.mkdir(parents=True)
    (package / "hms-agent.exe").write_bytes(b"entrypoint")
    manifest = build_agent_package_manifest(package, version="0.1.0")
    manifest_path = authority / "hms-agent.manifest.json"
    write_agent_package_manifest(manifest_path, manifest)

    runtime = SimpleNamespace(
        config=SimpleNamespace(
            package_source_root=package,
            package_manifest_path=manifest_path,
        )
    )
    preserved = tmp_path / "package-authority-preserved"
    redirected = tmp_path / "package-authority-redirected"
    redirected.mkdir()
    authority.rename(preserved)
    try:
        authority.symlink_to(redirected, target_is_directory=True)
    except OSError:
        preserved.rename(authority)
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(
        ManagedHyperVAgentQualificationError,
        match="authority path traverses",
    ):
        _load_host_package_authority(runtime)
