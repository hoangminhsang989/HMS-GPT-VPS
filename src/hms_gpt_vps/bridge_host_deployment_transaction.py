from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
import hashlib
import json
from pathlib import Path, PureWindowsPath
import secrets
import struct

from .agent_bridge_production_tls import provision_agent_bridge_production_tls_prerequisites
from .agent_bridge_tls_deployment import load_agent_bridge_tls_material
from .agent_transport_protocol import AgentDeviceCredential
from .bridge_oauth_introspection_credential import (
    BridgeOAuthIntrospectionCredential,
    load_protected_bridge_oauth_introspection_credential,
)
from .bridge_oauth_provisioning_ingress import provision_bridge_oauth_introspection_credential_from_stdin
from .bridge_package import BridgePackageManifest
from .bridge_package_deployment import (
    DEFAULT_BRIDGE_BINARY_PATH,
    finalize_bridge_package_service_acl,
    stage_bridge_package_create_only,
)
from .bridge_runtime_layout_provisioning import (
    provision_bridge_runtime_layout,
    validate_bridge_runtime_layout_authority,
)
from .bridge_service_dependency_loader import (
    provision_bridge_service_agent_credential,
    provision_bridge_service_pairing_key,
)
from .bridge_service_identity import HMS_BRIDGE_SERVICE_NAME, require_hms_bridge_service_sid
from .bridge_service_install import HmsBridgeServiceInstallConfig, install_hms_bridge_service_authority
from .bridge_service_provisioning_identity import prove_hms_bridge_provisioning_identity
from .bridge_service_runtime_config import BridgeServiceRuntimeConfig
from .bridge_service_runtime_config_publication import (
    canonical_bridge_service_runtime_config_bytes,
    publish_bridge_service_runtime_config_create_only,
)
from .bridge_service_config_storage import load_protected_bridge_service_runtime_config
from .bridge_service_secret_storage import (
    provision_bridge_service_secret_storage,
    prove_bridge_service_secret_storage,
)
from .bridge_tls_material_publication import (
    BRIDGE_TLS_CERTIFICATE_PATH,
    BRIDGE_TLS_PRIVATE_DIR,
    BRIDGE_TLS_PRIVATE_KEY_PATH,
    publish_bridge_tls_material_create_only,
)
from .pairing_exchange import PairingExchangeKey
from .powershell_direct import PowerShellDirectCredential
from .secure_mcp_tunnel import TunnelRuntimeApiKeyStore
from .secure_mcp_tunnel_package import (
    OPENAI_TUNNEL_CLIENT_SHA256,
    TunnelRuntimePackageConfig,
    provision_tunnel_runtime_package,
    prove_installed_tunnel_runtime,
)


HMS_BRIDGE_EXPECTED_SERVICE_SID = (
    "S-1-5-80-3027300117-82505545-3616633165-1729693371-3881641565"
)
_MAX_TUNNEL_API_KEY_BYTES = 16 * 1024


class BridgeHostDeploymentTransactionError(RuntimeError):
    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(f"{stage}: {message}")


def derive_windows_service_sid(service_name: str) -> str:
    if not isinstance(service_name, str) or not service_name or service_name != service_name.strip():
        raise ValueError("service_name must be canonical non-empty text")
    digest = hashlib.sha1(service_name.upper().encode("utf-16le")).digest()
    parts = struct.unpack("<IIIII", digest)
    return "S-1-5-80-" + "-".join(str(value) for value in parts)


def derive_hms_bridge_service_sid() -> str:
    value = derive_windows_service_sid(HMS_BRIDGE_SERVICE_NAME)
    if value != HMS_BRIDGE_EXPECTED_SERVICE_SID:
        raise BridgeHostDeploymentTransactionError(
            "service_sid",
            "derived HMSBridge SID differs from frozen authority",
        )
    return require_hms_bridge_service_sid(value)


def _same_windows_path(left: object, right: object) -> bool:
    return str(PureWindowsPath(str(left))).casefold() == str(PureWindowsPath(str(right))).casefold()


def _validate_tunnel_api_key_input(value: object) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise TypeError("tunnel_runtime_api_key must be non-empty canonical text")
    if any(char in value for char in ("\x00", "\r", "\n")):
        raise TypeError("tunnel_runtime_api_key contains a forbidden control character")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise TypeError("tunnel_runtime_api_key must be valid UTF-8 text") from exc
    if size > _MAX_TUNNEL_API_KEY_BYTES:
        raise TypeError("tunnel_runtime_api_key exceeds safety bound")
    if any(char not in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-" for char in value):
        raise TypeError("tunnel_runtime_api_key contains unsupported characters")


@dataclass(frozen=True)
class BridgeHostDeploymentRequest:
    source_package_root: Path
    package_manifest: BridgePackageManifest
    runtime_config: BridgeServiceRuntimeConfig
    tunnel_archive_path: Path
    agent_credential: AgentDeviceCredential = field(repr=False)
    oauth_credential: BridgeOAuthIntrospectionCredential = field(repr=False)
    tls_certificate_pem: bytes = field(repr=False)
    tls_private_key_pem: bytes = field(repr=False)
    guest_credential: PowerShellDirectCredential = field(repr=False)
    trust_root_certificate_pem: bytes = field(repr=False)
    tunnel_runtime_api_key: str = field(repr=False)

    def validate(self) -> None:
        if not isinstance(self.source_package_root, Path):
            raise TypeError("source_package_root must be pathlib.Path")
        if not isinstance(self.tunnel_archive_path, Path):
            raise TypeError("tunnel_archive_path must be pathlib.Path")
        if not isinstance(self.package_manifest, BridgePackageManifest):
            raise TypeError("package_manifest must be a BridgePackageManifest")
        if not isinstance(self.runtime_config, BridgeServiceRuntimeConfig):
            raise TypeError("runtime_config must be a BridgeServiceRuntimeConfig")
        if not isinstance(self.agent_credential, AgentDeviceCredential):
            raise TypeError("agent_credential must be an AgentDeviceCredential")
        if not isinstance(self.oauth_credential, BridgeOAuthIntrospectionCredential):
            raise TypeError("oauth_credential must be a BridgeOAuthIntrospectionCredential")
        if not isinstance(self.guest_credential, PowerShellDirectCredential):
            raise TypeError("guest_credential must be a PowerShellDirectCredential")
        if not isinstance(self.tls_certificate_pem, bytes) or not self.tls_certificate_pem:
            raise TypeError("tls_certificate_pem must be non-empty bytes")
        if not isinstance(self.tls_private_key_pem, bytes) or not self.tls_private_key_pem:
            raise TypeError("tls_private_key_pem must be non-empty bytes")
        if not isinstance(self.trust_root_certificate_pem, bytes) or not self.trust_root_certificate_pem:
            raise TypeError("trust_root_certificate_pem must be non-empty bytes")
        _validate_tunnel_api_key_input(self.tunnel_runtime_api_key)

        self.package_manifest.validate()
        self.runtime_config.validate()
        validate_bridge_runtime_layout_authority(self.runtime_config)
        self.agent_credential.validate()
        self.oauth_credential.validate()
        self.guest_credential.validate()

        if self.agent_credential.instance_id != self.runtime_config.instance_id:
            raise BridgeHostDeploymentTransactionError(
                "validate", "Agent credential instance_id differs from Bridge runtime instance_id"
            )
        if self.oauth_credential.issuer_url != self.runtime_config.mcp_issuer_url:
            raise BridgeHostDeploymentTransactionError(
                "validate", "OAuth credential issuer differs from MCP runtime issuer"
            )
        tls_paths = (
            (self.runtime_config.tls_certificate_path, BRIDGE_TLS_CERTIFICATE_PATH, "certificate"),
            (self.runtime_config.tls_private_key_path, BRIDGE_TLS_PRIVATE_KEY_PATH, "private key"),
            (self.runtime_config.tls_storage_root, BRIDGE_TLS_PRIVATE_DIR, "private-key storage root"),
        )
        for observed, expected, label in tls_paths:
            if not _same_windows_path(observed, expected):
                raise BridgeHostDeploymentTransactionError(
                    "validate", f"runtime TLS {label} path differs from fixed authority"
                )


def _run_stage(stage: str, callback):
    try:
        return callback()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise BridgeHostDeploymentTransactionError(stage, str(exc)) from exc


def deploy_hms_bridge_host_create_only(request: BridgeHostDeploymentRequest) -> dict[str, object]:
    """Provision complete host authority without starting HMSBridge or the tunnel."""

    request.validate()
    service_sid = derive_hms_bridge_service_sid()

    package = _run_stage(
        "package_stage",
        lambda: stage_bridge_package_create_only(request.source_package_root, request.package_manifest),
    )
    if not package.ready or package.binary_sha256 != request.package_manifest.sha256.lower():
        raise BridgeHostDeploymentTransactionError("package_stage", "package evidence differs from manifest")
    if not _same_windows_path(package.binary_path, DEFAULT_BRIDGE_BINARY_PATH):
        raise BridgeHostDeploymentTransactionError("package_stage", "package binary path differs from authority")

    service = _run_stage(
        "scm_install",
        lambda: install_hms_bridge_service_authority(
            HmsBridgeServiceInstallConfig(
                binary_path=package.binary_path,
                binary_sha256=package.binary_sha256,
                expected_service_sid=service_sid,
            )
        ),
    )
    if service.get("ready") is not True or service.get("service_sid") != service_sid:
        raise BridgeHostDeploymentTransactionError("scm_install", "SCM evidence differs from service authority")

    package_acl = _run_stage(
        "package_acl",
        lambda: finalize_bridge_package_service_acl(request.package_manifest),
    )
    if not package_acl.ready or package_acl.service_acl_finalized is not True:
        raise BridgeHostDeploymentTransactionError("package_acl", "package service ACL did not finalize")

    layout = _run_stage(
        "runtime_layout",
        lambda: provision_bridge_runtime_layout(request.runtime_config),
    )
    if layout.get("ready") is not True or layout.get("service_sid") != service_sid:
        raise BridgeHostDeploymentTransactionError("runtime_layout", "runtime layout evidence differs")

    runtime = _run_stage(
        "runtime_config_compile",
        lambda: request.runtime_config.to_runtime_config(service_sid),
    )

    tunnel_package = _run_stage(
        "tunnel_package",
        lambda: provision_tunnel_runtime_package(request.tunnel_archive_path),
    )
    if (
        tunnel_package.ready is not True
        or tunnel_package.archive_sha256 != OPENAI_TUNNEL_CLIENT_SHA256
        or tunnel_package.file_count != 5
    ):
        raise BridgeHostDeploymentTransactionError(
            "tunnel_package", "OpenAI tunnel runtime package evidence differs"
        )

    tls_material = _run_stage(
        "tls_material",
        lambda: publish_bridge_tls_material_create_only(
            runtime.tls,
            request.tls_certificate_pem,
            request.tls_private_key_pem,
        ),
    )
    if tls_material.get("ready") is not True or tls_material.get("runtime_listener_started") is not False:
        raise BridgeHostDeploymentTransactionError("tls_material", "TLS publication evidence differs")

    pre_secret_identity = _run_stage("pre_machine_secrets_identity", prove_hms_bridge_provisioning_identity)
    if pre_secret_identity.get("service_sid") != service_sid:
        raise BridgeHostDeploymentTransactionError("pre_machine_secrets_identity", "HMSBridge SID differs before machine secrets")

    pairing_key = _run_stage(
        "pairing_key",
        lambda: provision_bridge_service_pairing_key(runtime.secret_storage),
    )
    if not isinstance(pairing_key, PairingExchangeKey):
        raise BridgeHostDeploymentTransactionError("pairing_key", "pairing key authority returned invalid type")

    stored_agent = _run_stage(
        "agent_credential",
        lambda: provision_bridge_service_agent_credential(runtime.secret_storage, request.agent_credential),
    )
    if stored_agent.instance_id != request.agent_credential.instance_id or stored_agent.device_id != request.agent_credential.device_id:
        raise BridgeHostDeploymentTransactionError("agent_credential", "stored Agent credential identity differs")

    tunnel_key_store = TunnelRuntimeApiKeyStore(runtime.secret_storage)
    _run_stage("tunnel_api_key", lambda: tunnel_key_store.provision(request.tunnel_runtime_api_key))
    secret_acl = _run_stage(
        "tunnel_secret_acl",
        lambda: provision_bridge_service_secret_storage(
            runtime.secret_storage,
            require_pairing_key=True,
        ),
    )
    if secret_acl.get("ready") is not True or secret_acl.get("secret_file_acls_exact") is not True:
        raise BridgeHostDeploymentTransactionError(
            "tunnel_secret_acl", "tunnel API-key secret ACL did not converge"
        )
    loaded_tunnel_key = _run_stage("tunnel_api_key_load", tunnel_key_store.load)
    if not secrets.compare_digest(loaded_tunnel_key, request.tunnel_runtime_api_key):
        raise BridgeHostDeploymentTransactionError(
            "tunnel_api_key_load", "protected tunnel API-key readback differs"
        )
    loaded_tunnel_key = ""

    post_secret_identity = _run_stage("post_machine_secrets_identity", prove_hms_bridge_provisioning_identity)
    if post_secret_identity.get("service_sid") != service_sid:
        raise BridgeHostDeploymentTransactionError("post_machine_secrets_identity", "HMSBridge SID changed across machine secrets")

    tls_prerequisites = _run_stage(
        "tls_prerequisites",
        lambda: provision_agent_bridge_production_tls_prerequisites(
            runtime.tls,
            request.guest_credential,
            request.trust_root_certificate_pem,
        ),
    )
    if (
        tls_prerequisites.get("tls_material_preflight_ready") is not True
        or tls_prerequisites.get("firewall_ready") is not True
        or tls_prerequisites.get("guest_trust_root_present") is not True
        or tls_prerequisites.get("runtime_listener_started") is not False
    ):
        raise BridgeHostDeploymentTransactionError("tls_prerequisites", "TLS prerequisite evidence differs")

    config_evidence = _run_stage(
        "runtime_config_publish",
        lambda: publish_bridge_service_runtime_config_create_only(request.runtime_config),
    )
    if config_evidence.get("ready") is not True or config_evidence.get("service_sid") != service_sid:
        raise BridgeHostDeploymentTransactionError("runtime_config_publish", "runtime config evidence differs")

    oauth_payload = json.dumps(
        {
            "issuer_url": request.oauth_credential.issuer_url,
            "client_id": request.oauth_credential.client_id,
            "client_secret": request.oauth_credential.client_secret,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    oauth_evidence = _run_stage(
        "oauth_credential",
        lambda: provision_bridge_oauth_introspection_credential_from_stdin(BytesIO(oauth_payload)),
    )
    if (
        oauth_evidence.get("ready") is not True
        or oauth_evidence.get("service_sid") != service_sid
        or oauth_evidence.get("secret_acl_exact") is not True
        or oauth_evidence.get("issuer_url") != request.oauth_credential.issuer_url
        or oauth_evidence.get("client_id") != request.oauth_credential.client_id
    ):
        raise BridgeHostDeploymentTransactionError("oauth_credential", "OAuth provisioning evidence differs")
    loaded_oauth = _run_stage(
        "oauth_protected_load",
        lambda: load_protected_bridge_oauth_introspection_credential(request.runtime_config.mcp_issuer_url),
    )
    if loaded_oauth != request.oauth_credential:
        raise BridgeHostDeploymentTransactionError("oauth_protected_load", "OAuth protected load differs from provisioned identity")

    final_config = _run_stage("final_config_proof", load_protected_bridge_service_runtime_config)
    if canonical_bridge_service_runtime_config_bytes(final_config) != canonical_bridge_service_runtime_config_bytes(request.runtime_config):
        raise BridgeHostDeploymentTransactionError("final_config_proof", "final runtime config differs")
    final_tls = _run_stage("final_tls_proof", lambda: load_agent_bridge_tls_material(runtime.tls.material))
    final_tls.validate()
    final_secret = _run_stage(
        "final_secret_proof",
        lambda: prove_bridge_service_secret_storage(runtime.secret_storage, require_pairing_key=True),
    )
    if final_secret.get("ready") is not True or final_secret.get("secret_file_acls_exact") is not True:
        raise BridgeHostDeploymentTransactionError("final_secret_proof", "final secret authority differs")
    final_tunnel_key = _run_stage("final_tunnel_key_proof", tunnel_key_store.load)
    if not secrets.compare_digest(final_tunnel_key, request.tunnel_runtime_api_key):
        raise BridgeHostDeploymentTransactionError("final_tunnel_key_proof", "final tunnel key authority differs")
    final_tunnel_key = ""
    final_tunnel = _run_stage(
        "final_tunnel_package_proof",
        lambda: prove_installed_tunnel_runtime(
            TunnelRuntimePackageConfig(),
            service_sid=service_sid,
            prove_acl=True,
        ),
    )
    if final_tunnel.ready is not True or final_tunnel.archive_sha256 != OPENAI_TUNNEL_CLIENT_SHA256:
        raise BridgeHostDeploymentTransactionError("final_tunnel_package_proof", "final tunnel package authority differs")
    final_identity = _run_stage("final_identity", prove_hms_bridge_provisioning_identity)
    if (
        final_identity.get("service_sid") != service_sid
        or final_identity.get("service_state") != "Stopped"
        or final_identity.get("service_start_mode") != "Manual"
    ):
        raise BridgeHostDeploymentTransactionError("final_identity", "HMSBridge is not exact Stopped/Manual authority")

    return {
        "ready": True,
        "status": "STAGED_NOT_EXECUTED",
        "service_name": HMS_BRIDGE_SERVICE_NAME,
        "service_sid": service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "package_sha256": package.binary_sha256,
        "runtime_config_sha256": hashlib.sha256(
            canonical_bridge_service_runtime_config_bytes(request.runtime_config)
        ).hexdigest(),
        "tls_certificate_der_sha256": runtime.tls.material.certificate_der_sha256,
        "tls_private_key_file_sha256": runtime.tls.material.private_key_file_sha256,
        "agent_instance_id": request.agent_credential.instance_id,
        "agent_device_id": request.agent_credential.device_id,
        "oauth_issuer_url": request.oauth_credential.issuer_url,
        "oauth_client_id": request.oauth_credential.client_id,
        "tunnel_id": request.runtime_config.tunnel_id,
        "tunnel_archive_sha256": final_tunnel.archive_sha256,
        "package_service_acl_finalized": True,
        "runtime_layout_ready": True,
        "runtime_config_ready": True,
        "pairing_key_ready": True,
        "agent_credential_ready": True,
        "oauth_credential_ready": True,
        "tunnel_package_ready": True,
        "tunnel_api_key_ready": True,
        "tls_material_ready": True,
        "firewall_ready": True,
        "guest_trust_root_present": True,
        "runtime_listener_started": False,
        "tunnel_runtime_started": False,
        "tunnel_ready": False,
        "live_managed_guest_tls_proven": False,
        "authenticated_agent_transport_proven": False,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
    }
