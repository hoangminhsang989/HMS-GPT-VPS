from __future__ import annotations

from pathlib import Path

import pytest

import hms_gpt_vps.agent_bridge_production_tls as runtime_module
from hms_gpt_vps.agent_bridge_firewall import AgentBridgeFirewallConfig
from hms_gpt_vps.agent_bridge_http_boundary import AgentBridgeHttpBoundary
from hms_gpt_vps.agent_bridge_production_tls import (
    AgentBridgeProductionTlsConfig,
    AgentBridgeProductionTlsRuntimeError,
    provision_agent_bridge_production_tls_prerequisites,
    qualify_agent_bridge_production_tls,
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
    return AgentBridgeProductionTlsConfig(
        firewall=AgentBridgeFirewallConfig(network=network),
        storage=AgentBridgePrivateKeyStorageConfig(
            storage_root=storage_root,
            private_key_path=key_path,
            private_key_file_sha256=_KEY_SHA256,
            bridge_reader_sid=_SERVICE_SID,
        ),
        material=AgentBridgeTlsMaterialConfig(
            network=network,
            certificate_path=tmp_path / "agent-bridge.pem",
            private_key_path=key_path,
            certificate_der_sha256=_CERT_SHA256,
            private_key_file_sha256=_KEY_SHA256,
        ),
        guest=ManagedGuestBridgeTlsConfig(
            network=network,
            vm_id=_VM_ID,
            vm_name="HMS-VPS-1",
            bridge_origin="https://172.29.240.1:9443",
            server_certificate_der_sha256=_CERT_SHA256,
            trust_root_der_sha256=_ROOT_SHA256,
        ),
    )


def _credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential(username="bootstrap", password="secret")


def _boundary() -> AgentBridgeHttpBoundary:
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


def test_service_runtime_never_accepts_guest_credential_or_trust_payload(
    tmp_path: Path,
) -> None:
    import inspect

    signature = inspect.signature(start_agent_bridge_production_tls)
    assert list(signature.parameters) == ["boundary", "config"]


def test_privileged_provisioning_does_not_start_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    calls: list[str] = []

    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_private_key_storage",
        lambda cfg: calls.append("storage") or {"ready": True, "changed": True},
    )
    monkeypatch.setattr(
        runtime_module,
        "load_agent_bridge_tls_material",
        lambda cfg: calls.append("material") or _FakeMaterial(),
    )
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_firewall",
        lambda cfg: calls.append("firewall") or {"ready": True, "created": True},
    )
    monkeypatch.setattr(
        runtime_module,
        "install_managed_guest_bridge_trust_root_by_id",
        lambda cfg, credential, pem: calls.append("trust") or {
            "present": True,
            "changed": True,
            "sha256": _ROOT_SHA256,
        },
    )
    monkeypatch.setattr(
        runtime_module,
        "build_agent_bridge_tls_server",
        lambda *args: pytest.fail("privileged provisioning must not start listener"),
    )

    proof = provision_agent_bridge_production_tls_prerequisites(
        config,
        _credential(),
        b"root",
    )
    assert calls == ["storage", "material", "firewall", "trust"]
    assert proof["runtime_listener_started"] is False
    assert proof["live_managed_guest_tls_proven"] is False
    assert proof["pairing_ready"] is False


def test_service_runtime_uses_only_identity_storage_material_and_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    calls: list[str] = []
    server = _FakeServer()

    monkeypatch.setattr(
        runtime_module,
        "prove_agent_bridge_process_reader_identity",
        lambda cfg: calls.append("identity") or {
            "process_sid": _SERVICE_SID,
            "identity_name": r"NT SERVICE\HMSBridge",
            "dedicated_service_sid": True,
        },
    )
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_private_key_storage",
        lambda cfg: calls.append("storage") or {"ready": True, "changed": False},
    )
    monkeypatch.setattr(
        runtime_module,
        "load_agent_bridge_tls_material",
        lambda cfg: calls.append("material") or _FakeMaterial(),
    )
    monkeypatch.setattr(
        runtime_module,
        "build_agent_bridge_tls_server",
        lambda boundary, material: calls.append("build") or server,
    )
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_firewall",
        lambda cfg: pytest.fail("service runtime must not mutate/probe firewall"),
    )
    monkeypatch.setattr(
        runtime_module,
        "install_managed_guest_bridge_trust_root_by_id",
        lambda *args: pytest.fail("service runtime must not use PowerShell Direct"),
    )
    monkeypatch.setattr(
        runtime_module,
        "probe_managed_guest_bridge_tls_by_id",
        lambda *args: pytest.rail("service runtime must not use guest credential"),
    )

    runtime = start_agent_bridge_production_tls(_boundary(), config)
    assert calls == ["identity", "storage", "material", "build"]
    assert runtime.bound_address == ("172.29.240.1", 9443)
    assert runtime.evidence["privileged_provisioning_performed_by_runtime"] is False
    assert runtime.evidence["live_managed_guest_tls_proven"] is False
    assert runtime.evidence["pairing_ready"] is False
    runtime.shutdown()


def test_service_runtime_rejects_acl_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(
        runtime_module,
        "prove_agent_bridge_process_reader_identity",
        lambda cfg: {
            "process_sid": _SERVICE_SID,
            "identity_name": r"NT SERVICE\HMSBridge",
            "dedicated_service_sid": True,
        },
    )
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_private_key_storage",
        lambda cfg: {"ready": True, "changed": True},
    )
    monkeypatch.setattr(
        runtime_module,
        "load_agent_bridge_tls_material",
        lambda cfg: pytest.fail("must fail before reading TLS material"),
    )

    with pytest.raises(
        AgentBridgeProductionTlsRuntimeError,
        match="must not reconcile",
    ):
        start_agent_bridge_production_tls(_boundary(), config)


def test_privileged_qualification_requires_live_guest_tls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_firewall",
        lambda cfg: calls.append("firewall") or {"ready": True, "created": False},
    )
    monkeypatch.setattr(
        runtime_module,
        "install_managed_guest_bridge_trust_root_by_id",
        lambda cfg, credential, pem: calls.append("trust") or {
            "present": True,
            "changed": False,
            "sha256": _ROOT_SHA256,
        },
    )
    monkeypatch.setattr(
        runtime_module,
        "probe_managed_guest_bridge_tls_by_id",
        lambda cfg, credential: calls.append("probe") or {
            "live_managed_guest_tls_proven": True,
            "server_certificate_sha256": _CERT_SHA256,
            "vm_id": _VM_ID,
            "bridge_origin": cfg.bridge_origin,
        },
    )

    proof = qualify_agent_bridge_production_tls(config, _credential(), b"root")
    assert calls == ["firewall", "trust", "probe"]
    assert proof["live_managed_guest_tls_proven"] is True
    assert proof["authenticated_agent_transport_proven"] is False
    assert proof["full_bridge_command_flow_proven"] is False
    assert proof["bootstrap_retired"] is False
    assert proof["pairing_ready"] is False


def test_privileged_qualification_rejects_wrong_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(
        runtime_module,
        "ensure_agent_bridge_firewall",
        lambda cfg: {"ready": True, "created": False},
    )
    monkeypatch.setattr(
        runtime_module,
        "install_managed_guest_bridge_trust_root_by_id",
        lambda cfg, credential, pem: {
            "present": True,
            "changed": False,
            "sha256": _ROOT_SHA256,
        },
    )
    monkeypatch.setattr(
        runtime_module,
        "probe_managed_guest_bridge_tls_by_id",
        lambda cfg, credential: {
            "live_managed_guest_tls_proven": True,
            "server_certificate_sha256": "d" * 64,
            "vm_id": _VM_ID,
            "bridge_origin": cfg.bridge_origin,
        },
    )

    with pytest.raises(
        AgentBridgeProductionTlsRuntimeError,
        match="wrong production TLS certificate",
    ):
        qualify_agent_bridge_production_tls(config, _credential(), b"root")
