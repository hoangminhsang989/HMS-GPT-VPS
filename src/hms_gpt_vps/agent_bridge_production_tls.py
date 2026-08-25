from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .agent_bridge_firewall import (
    AgentBridgeFirewallConfig,
    ensure_agent_bridge_firewall,
)
from .agent_bridge_http_boundary import AgentBridgeHttpBoundary
from .agent_bridge_tls_deployment import (
    AgentBridgeTlsMaterialConfig,
    ManagedGuestBridgeTlsConfig,
    build_agent_bridge_tls_server,
    install_managed_guest_bridge_trust_root_by_id,
    load_agent_bridge_tls_material,
    probe_managed_guest_bridge_tls_by_id,
)
from .agent_bridge_tls_storage import (
    AgentBridgePrivateKeyStorageConfig,
    ensure_agent_bridge_private_key_storage,
    prove_agent_bridge_process_reader_identity,
)
from .powershell_direct import PowerShellDirectCredential


class AgentBridgeProductionTlsRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentBridgeProductionTlsConfig:
    firewall: AgentBridgeFirewallConfig
    storage: AgentBridgePrivateKeyStorageConfig
    material: AgentBridgeTlsMaterialConfig
    guest: ManagedGuestBridgeTlsConfig

    def validate(self) -> None:
        if not isinstance(self.firewall, AgentBridgeFirewallConfig):
            raise TypeError("firewall must be an AgentBridgeFirewallConfig")
        if not isinstance(self.storage, AgentBridgePrivateKeyStorageConfig):
            raise TypeError("storage must be an AgentBridgePrivateKeyStorageConfig")
        if not isinstance(self.material, AgentBridgeTlsMaterialConfig):
            raise TypeError("material must be an AgentBridgeTlsMaterialConfig")
        if not isinstance(self.guest, ManagedGuestBridgeTlsConfig):
            raise TypeError("guest must be a ManagedGuestBridgeTlsConfig")
        self.firewall.validate()
        self.storage.validate()
        self.material.validate()
        self.guest.validate()

        if self.firewall.network != self.material.network:
            raise AgentBridgeProductionTlsRuntimeError(
                "firewall and TLS material use different Hyper-V network authority"
            )
        if self.firewall.network != self.guest.network:
            raise AgentBridgeProductionTlsRuntimeError(
                "firewall and managed guest use different Hyper-V network authority"
            )
        if self.firewall.port != self.material.port or self.firewall.port != self.guest.port:
            raise AgentBridgeProductionTlsRuntimeError(
                "production TLS components use different listener ports"
            )
        if self.storage.private_key_path != self.material.private_key_path:
            raise AgentBridgeProductionTlsRuntimeError(
                "private-key storage and TLS material use different key paths"
            )
        if (
            self.storage.private_key_file_sha256
            != self.material.private_key_file_sha256
        ):
            raise AgentBridgeProductionTlsRuntimeError(
                "private-key storage and TLS material use different key identities"
            )
        if (
            self.material.certificate_der_sha256
            != self.guest.server_certificate_der_sha256
        ):
            raise AgentBridgeProductionTlsRuntimeError(
                "host TLS material and guest qualification use different leaf identities"
            )
        if self.material.bridge_origin != self.guest.bridge_origin:
            raise AgentBridgeProductionTlsRuntimeError(
                "host TLS material and guest qualification use different Bridge origins"
            )


@dataclass
class AgentBridgeProductionTlsRuntime:
    config: AgentBridgeProductionTlsConfig
    server: Any
    evidence: dict[str, object]
    _closed: bool = False

    @property
    def bound_address(self) -> tuple[str, int]:
        address = getattr(self.server, "bound_address", None)
        if (
            not isinstance(address, tuple)
            or len(address) != 2
            or address[0] != self.config.firewall.network.gateway
            or address[1] != self.config.firewall.port
        ):
            raise AgentBridgeProductionTlsRuntimeError(
                "production TLS server lost exact managed bind authority"
            )
        return address

    def shutdown(self) -> None:
        if self._closed:
            return
        self.server.shutdown()
        self._closed = True

    def __enter__(self) -> "AgentBridgeProductionTlsRuntime":
        _ = self.bound_address
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()


def start_agent_bridge_production_tls(
    boundary: AgentBridgeHttpBoundary,
    config: AgentBridgeProductionTlsConfig,
    credential: PowerShellDirectCredential,
    trust_root_certificate_pem: bytes,
) -> AgentBridgeProductionTlsRuntime:
    """Start and qualify the exact private Hyper-V Agent Bridge TLS path.

    This is a fail-closed production orchestration boundary. It secures the
    dedicated private-key storage before reading the key, verifies the exact
    firewall authority, starts the TLS listener, publishes the pinned trust root
    to the VMId-bound managed guest, and proves a trusted live TLS handshake from
    that guest. It does not claim authenticated Agent transport or pairing.
    """

    if not isinstance(boundary, AgentBridgeHttpBoundary):
        raise TypeError("boundary must be an AgentBridgeHttpBoundary")
    if not isinstance(config, AgentBridgeProductionTlsConfig):
        raise TypeError("config must be an AgentBridgeProductionTlsConfig")
    if not isinstance(credential, PowerShellDirectCredential):
        raise TypeError("credential must be a PowerShellDirectCredential")
    if not isinstance(trust_root_certificate_pem, bytes):
        raise TypeError("trust_root_certificate_pem must be bytes")
    config.validate()
    credential.validate()

    identity_evidence = prove_agent_bridge_process_reader_identity(config.storage)

    storage_evidence = ensure_agent_bridge_private_key_storage(config.storage)
    if storage_evidence.get("ready") is not True:
        raise AgentBridgeProductionTlsRuntimeError(
            "private-key storage gate did not prove readiness"
        )
    if storage_evidence.get("changed") is not False:
        raise AgentBridgeProductionTlsRuntimeError(
            "production Bridge runtime must not reconcile private-key ACLs"
        )

    material = load_agent_bridge_tls_material(config.material)
    material.validate()

    firewall_evidence = ensure_agent_bridge_firewall(config.firewall)
    if firewall_evidence.get("ready") is not True:
        raise AgentBridgeProductionTlsRuntimeError(
            "firewall gate did not prove readiness"
        )

    server = build_agent_bridge_tls_server(boundary, material)
    started = False
    try:
        bound_address = server.start()
        started = True
        expected_address = (
            config.firewall.network.gateway,
            config.firewall.port,
        )
        if bound_address != expected_address:
            raise AgentBridgeProductionTlsRuntimeError(
                "production TLS listener started on the wrong authority"
            )

        trust_evidence = install_managed_guest_bridge_trust_root_by_id(
            config.guest,
            credential,
            trust_root_certificate_pem,
        )
        if trust_evidence.get("present") is not True:
            raise AgentBridgeProductionTlsRuntimeError(
                "managed guest trust-root gate did not prove readiness"
            )

        tls_evidence = probe_managed_guest_bridge_tls_by_id(
            config.guest,
            credential,
        )
        if tls_evidence.get("live_managed_guest_tls_proven") is not True:
            raise AgentBridgeProductionTlsRuntimeError(
                "live managed-guest TLS gate did not prove readiness"
            )

        # Re-read the server's own runtime bind state after the guest proof.
        current_address = getattr(server, "bound_address", None)
        if current_address != expected_address:
            raise AgentBridgeProductionTlsRuntimeError(
                "production TLS listener authority changed during qualification"
            )

        if trust_evidence.get("sha256") != config.guest.trust_root_der_sha256:
            raise AgentBridgeProductionTlsRuntimeError(
                "managed guest trust-root identity changed during orchestration"
            )
        if (
            tls_evidence.get("server_certificate_sha256")
            != config.material.certificate_der_sha256
        ):
            raise AgentBridgeProductionTlsRuntimeError(
                "managed guest observed the wrong production TLS certificate"
            )

        evidence: dict[str, object] = {
            "bridge_process_sid_proven": True,
            "bridge_process_sid": identity_evidence["process_sid"],
            "private_key_storage_ready": True,
            "private_key_storage_changed": storage_evidence["changed"],
            "firewall_ready": True,
            "firewall_created": firewall_evidence["created"],
            "tls_listener_started": True,
            "tls_listener_host": expected_address[0],
            "tls_listener_port": expected_address[1],
            "guest_trust_root_present": True,
            "guest_trust_root_changed": trust_evidence["changed"],
            "guest_trust_root_sha256": trust_evidence["sha256"],
            "live_managed_guest_tls_proven": True,
            "server_certificate_sha256": tls_evidence[
                "server_certificate_sha256"
            ],
            "vm_id": tls_evidence["vm_id"],
            "bridge_origin": tls_evidence["bridge_origin"],
            # R002F proof boundary remains closed until later tranches.
            "authenticated_agent_transport_proven": False,
            "full_bridge_command_flow_proven": False,
            "bootstrap_retired": False,
            "pairing_ready": False,
        }
        return AgentBridgeProductionTlsRuntime(
            config=config,
            server=server,
            evidence=evidence,
        )
    except Exception:
        if started:
            try:
                server.shutdown()
            except Exception as shutdown_exc:
                raise AgentBridgeProductionTlsRuntimeError(
                    "production TLS qualification failed and listener shutdown also failed"
                ) from shutdown_exc
        raise
