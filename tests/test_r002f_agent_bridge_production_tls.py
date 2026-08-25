from __future__ import annotations

from pathlib import Path

import pytest

import hms_gpt_vps.agent_bridge_production_tls as runtime_module
from hms_gpt_vps.agent_bridge_firewall import AgentBridgeFirewallConfig
from hms_gpt_vps.agent_bridge_http_boundary import AgentBridgeHttpBoundary
from hms_gpt_vps.agent_bridge_production_tls import (
    AgentBridgeProductionTlsConfig,
    AgentBridgeProductionTlsRuntimeError,
    start_agent_bridge_production_tls,
)
from hms_gpt_vps.agent_bridge_tls_deployment import (
    AgentBridgeTlsMaterialConfig,
    ManagedGuestBridgeTlsConfig,
)
from hms_gpt_vps.agent_bridge_tls_storage import AgentBridgePrivateKeyStorageConfig
from hms_gpt_vps.hyperv_network import HyperVNetworkConfig
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential


_SERVICE_SID = "S-1-5-80-123-456-789-1011-1213"
_KEY_SHA256 = "a" * 64
_CERT_SHA256 = "b" * 64
_ROOT_SHA256 = "c" * 64
_VM_ID = "12345678-1234-1234-1234-123456789abc"


def _config(tmp_path: Path) -> AgentBridgeProductionTlsConfig:
    network = HyperVNetworkConfig()
    storage_root = tmp_path / "tls-private-key"
    key_path = storage_root / "agent-bridge-private-key.pem"
    storage = AgentBridgePrivateKeyStorageConfig(
        storage_root=storage_root,
        private_key_path=key_path,
        private_key_file_sha256=_KEY_SHA256,
        bridge_reader_sid=_SERVICE_SID,
    )
    material = AgentBridgeTlsMaterialConfig(
        network=network,
        certificate_path=tmp_path / "agent-bridge.pem",
        private_key_path=key_path,
        certificate_der_sha256=_CERT_SHA256,
        private_key_file_sha256=_KEY_SHA256,
    )
    guest = ManagedGuestBridgeTlsConfig(
        network=network,
        vm_id=_VM_ID,
        vm_name="HMS-VPS-1",
        bridge_origin="https://172.29.240.1:9443",
        server_certificate_der_sha256=_CERT_SHA256,
        trust_root_der_sha256=_ROOT_SHA256,
    )
    return AgentBridgeProductionTlsConfig(
        firewall=AgentBridgeFirewallConfig(network=network),
        storage=storage,
        material=material,
        guest=guest,
    )


def _boundary_without_service() -> AgentBridgeHttpBoundary:
    # The orchestration test replaces server construction before the boundary is
    # dereferenced; bypassing __init__ keeps this test focused on orchestration.
    return object.__new__(AgentBridgeHttpBoundary)


class _FakeMaterial:
    def validate(self) -> None:
        return


class _FakeServer:
    def __init__(self) -> None:
        self.bound_address: tuple[str, int] | None = None
        self.shutdown_count = 0

    def start(self) -> tuple[str, int]:
        self.bound_address = ("172.29.240.1", 9443)
        return self.bound_address

    def shutdown(self) -> None:
        self.shutdown_count += 1
        self.bound_address = None


def test_production_config_rejects_private_key_identity_mismatch(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    bad_material = AgentBridgeTlsMaterialConfig(
        network=config.material.network,
        certificate_path=config.material.certificate_path,
        private_key_path=config.material.private_key_path,
        certificate_der_sha256=_CERT_SHA256,
        private_key_file_sha256="d" * 64,
    )
    bad = AgentBridgeProductionTlsConfig(
        firewall=config.firewall,
        storage=config.storage,
        material=bad_material,
        guest=config.guest,
    )

    with pytest.raises(
        AgentBridgeProductionTlsRuntimeError,
        match="key identities",
    ):
        bad.validate()


def _install_success_stubs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    probe_raises: bool = False,
):
    config = _config(tmp_path)
    calls: list[str] = []
    server = _FakeServer()

    monkeypatch.setattr(
        runtime_module,
        "prove_agent_bridge_process_reader_identity",
        lambda cfg: calls.append("identity")
        or {
            "process_sid": _SERVICE_SID,
            "identity_name": r"NT SERVICE\HMSBridge",
            "dedicated_service_sid": True,
        },
    )
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_private_key_storage",
        lambda cfg: calls.append("storage")
        or {"ready": True, "changed": False},
    )
    monkeypatch.setattr(
        runtime_module,
        "load_agent_bridge_tls_material",
        lambda cfg: calls.append("material") or _FakeMaterial(),
    )
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_firewall",
        lambda cfg: calls.append("firewall")
        or {"ready": True, "created": False},
    )
    monkeypatch.setattr(
        runtime_module,
        "build_agent_bridge_tls_server",
        lambda boundary, material: calls.append("build") or server,
    )
    monkeypatch.setattr(
        runtime_module,
        "install_managed_guest_bridge_trust_root_by_id",
        lambda cfg, credential, pem: calls.append("trust")
        or {
            "present": True,
            "changed": False,
            "sha256": _ROOT_SHA256,
        },
    )
    if probe_raises:
        def fail_probe(cfg, credential):
            calls.append("probe")
            raise RuntimeError("probe failed")
        monkeypatch.setattr(
            runtime_module,
            "probe_managed_guest_bridge_tls_by_id",
            fail_probe,
        )
    else:
        monkeypatch.setattr(
            runtime_module,
            "probe_managed_guest_bridge_tls_by_id",
            lambda cfg, credential: calls.append("probe")
            or {
                "live_managed_guest_tls_proven": True,
                "server_certificate_sha256": _CERT_SHA256,
                "vm_id": _VM_ID,
                "bridge_origin": config.guest.bridge_origin,
            },
        )
    return config, calls, server


def test_orchestration_runs_exact_order_and_keeps_later_proofs_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, calls, server = _install_success_stubs(tmp_path, monkeypatch)
    runtime = start_agent_bridge_production_tls(
        _boundary_without_service(),
        config,
        PowerShellDirectCredential(username="bootstrap", password="secret"),
        b"root-certificate",
    )

    assert calls == [
        "identity",
        "storage",
        "material",
        "firewall",
        "build",
        "trust",
        "probe",
    ]
    assert runtime.bound_address == ("172.29.240.1", 9443)
    assert runtime.evidence["bridge_process_sid_proven"] is True
    assert runtime.evidence["live_managed_guest_tls_proven"] is True
    assert runtime.evidence["authenticated_agent_transport_proven"] is False
    assert runtime.evidence["full_bridge_command_flow_proven"] is False
    assert runtime.evidence["bootstrap_retired"] is False
    assert runtime.evidence["pairing_ready"] is False

    runtime.shutdown()
    assert server.shutdown_count == 1


def test_orchestration_rejects_acl_reconciliation_in_service_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, calls, server = _install_success_stubs(tmp_path, monkeypatch)
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_private_key_storage",
        lambda cfg: calls.append("storage-remediated")
        or {"ready": True, "changed": True},
    )

    with pytest.raises(
        AgentBridgeProductionTlsRuntimeError,
        match="must not reconcile",
    ):
        start_agent_bridge_production_tls(
            _boundary_without_service(),
            config,
            PowerShellDirectCredential(username="bootstrap", password="secret"),
            b"root-certificate",
        )

    assert server.shutdown_count == 0


def test_orchestration_shutdowns_listener_on_guest_probe_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, calls, server = _install_success_stubs(
        tmp_path,
        monkeypatch,
        probe_raises=True,
    )

    with pytest.raises(RuntimeError, match="probe failed"):
        start_agent_bridge_production_tls(
            _boundary_without_service(),
            config,
            PowerShellDirectCredential(username="bootstrap", password="secret"),
            b"root-certificate",
        )

    assert calls[-1] == "probe"
    assert server.shutdown_count == 1
