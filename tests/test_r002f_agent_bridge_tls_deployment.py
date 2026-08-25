from __future__ import annotations

import hashlib
from pathlib import Path
import ssl

import pytest

import hms_gpt_vps.agent_bridge_tls_deployment as deployment_module
from hms_gpt_vps.agent_bridge_tls_deployment import (
    AgentBridgeTlsDeploymentError,
    AgentBridgeTlsMaterialConfig,
    ManagedGuestBridgeTlsConfig,
    build_managed_guest_bridge_tls_probe_script,
    install_managed_guest_bridge_trust_root_by_id,
    load_agent_bridge_tls_material,
    probe_managed_guest_bridge_tls_by_id,
)
from hms_gpt_vps.hyperv_network import HyperVNetworkConfig
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential


VM_ID = "12345678-1234-5678-1234-567812345678"
SERVER_DER = b"production-leaf-der"
ROOT_DER = b"production-root-der"
SERVER_SHA256 = hashlib.sha256(SERVER_DER).hexdigest()
ROOT_SHA256 = hashlib.sha256(ROOT_DER).hexdigest()


def pem_for(der: bytes) -> bytes:
    return ssl.DER_cert_to_PEM_cert(der).encode("ascii")


def guest_config(**overrides: object) -> ManagedGuestBridgeTlsConfig:
    values: dict[str, object] = {
        "network": HyperVNetworkConfig(),
        "vm_id": VM_ID,
        "vm_name": "HMS-VPS-000001",
        "bridge_origin": "https://172.29.240.1:9443",
        "server_certificate_der_sha256": SERVER_SHA256,
        "trust_root_der_sha256": ROOT_SHA256,
    }
    values.update(overrides)
    return ManagedGuestBridgeTlsConfig(**values)  # type: ignore[arg-type]


def exact_tls_result(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "tcp_connected": True,
        "tls_authenticated": True,
        "tls_encrypted": True,
        "tls_signed": True,
        "local_ip": "172.29.240.10",
        "remote_ip": "172.29.240.1",
        "remote_port": 9443,
        "target_host": "172.29.240.1",
        "tls_protocol": "Tls12",
        "server_certificate_sha256": SERVER_SHA256,
        "server_certificate_subject": "CN=172.29.240.1",
        "server_certificate_issuer": "CN=HMS Bridge Root",
    }
    result.update(overrides)
    return result


def exact_trust_result(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "changed": True,
        "present": True,
        "sha256": ROOT_SHA256,
        "thumbprint": "AA11",
        "subject": "CN=HMS Bridge Root",
        "issuer": "CN=HMS Bridge Root",
        "store": r"LocalMachine\Root",
        "certificate_authority": True,
    }
    result.update(overrides)
    return result


def test_material_config_pins_exact_managed_origin(tmp_path: Path) -> None:
    cert = tmp_path / "bridge-cert.pem"
    key = tmp_path / "bridge-key.pem"
    config = AgentBridgeTlsMaterialConfig(
        network=HyperVNetworkConfig(),
        certificate_path=cert,
        private_key_path=key,
        certificate_der_sha256="a" * 64,
        private_key_file_sha256="b" * 64,
    )

    config.validate()
    assert config.bridge_origin == "https://172.29.240.1:9443"


@pytest.mark.parametrize(
    "value",
    [
        "A" * 64,
        "a" * 63,
        "g" * 64,
        "",
    ],
)
def test_material_config_rejects_noncanonical_sha256(
    tmp_path: Path,
    value: str,
) -> None:
    with pytest.raises(AgentBridgeTlsDeploymentError):
        AgentBridgeTlsMaterialConfig(
            network=HyperVNetworkConfig(),
            certificate_path=tmp_path / "cert.pem",
            private_key_path=tmp_path / "key.pem",
            certificate_der_sha256=value,
            private_key_file_sha256="b" * 64,
        ).validate()


def test_material_config_rejects_same_cert_and_key_path(tmp_path: Path) -> None:
    same = tmp_path / "same.pem"
    with pytest.raises(AgentBridgeTlsDeploymentError, match="paths must differ"):
        AgentBridgeTlsMaterialConfig(
            network=HyperVNetworkConfig(),
            certificate_path=same,
            private_key_path=same,
            certificate_der_sha256="a" * 64,
            private_key_file_sha256="b" * 64,
        ).validate()


def test_load_material_pins_cert_key_and_tls_floor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cert = tmp_path / "bridge-cert.pem"
    key = tmp_path / "bridge-key.pem"
    cert.write_bytes(pem_for(SERVER_DER))
    key_bytes = (
        b"-----BEGIN PRIVATE KEY-----\n"
        b"ZmFrZS1wcm9kdWN0aW9uLWtleQ==\n"
        b"-----END PRIVATE KEY-----\n"
    )
    key.write_bytes(key_bytes)

    loaded_paths: list[tuple[str, str]] = []

    class FakeContext:
        protocol = ssl.PROTOCOL_TLS_SERVER

        def __init__(self) -> None:
            self.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            self.options = 0

        def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
            loaded_paths.append((certfile, keyfile))

    monkeypatch.setattr(
        deployment_module.ssl,
        "SSLContext",
        lambda protocol: FakeContext(),
    )
    config = AgentBridgeTlsMaterialConfig(
        network=HyperVNetworkConfig(),
        certificate_path=cert,
        private_key_path=key,
        certificate_der_sha256=SERVER_SHA256,
        private_key_file_sha256=hashlib.sha256(key_bytes).hexdigest(),
    )

    loaded = load_agent_bridge_tls_material(config)

    assert loaded.certificate_der_sha256 == SERVER_SHA256
    assert loaded.private_key_file_sha256 == hashlib.sha256(key_bytes).hexdigest()
    assert loaded.ssl_context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert loaded_paths == [(str(cert.absolute()), str(key.absolute()))]


def test_load_material_rejects_encrypted_private_key(
    tmp_path: Path,
) -> None:
    cert = tmp_path / "bridge-cert.pem"
    key = tmp_path / "bridge-key.pem"
    cert.write_bytes(pem_for(SERVER_DER))
    key_bytes = (
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        b"ZmFrZQ==\n"
        b"-----END ENCRYPTED PRIVATE KEY-----\n"
    )
    key.write_bytes(key_bytes)
    config = AgentBridgeTlsMaterialConfig(
        network=HyperVNetworkConfig(),
        certificate_path=cert,
        private_key_path=key,
        certificate_der_sha256=SERVER_SHA256,
        private_key_file_sha256=hashlib.sha256(key_bytes).hexdigest(),
    )

    with pytest.raises(AgentBridgeTlsDeploymentError, match="deployment-unlocked"):
        load_agent_bridge_tls_material(config)


def test_load_material_rejects_unpinned_certificate(
    tmp_path: Path,
) -> None:
    cert = tmp_path / "bridge-cert.pem"
    key = tmp_path / "bridge-key.pem"
    cert.write_bytes(pem_for(SERVER_DER))
    key_bytes = (
        b"-----BEGIN PRIVATE KEY-----\n"
        b"ZmFrZQ==\n"
        b"-----END PRIVATE KEY-----\n"
    )
    key.write_bytes(key_bytes)
    config = AgentBridgeTlsMaterialConfig(
        network=HyperVNetworkConfig(),
        certificate_path=cert,
        private_key_path=key,
        certificate_der_sha256="0" * 64,
        private_key_file_sha256=hashlib.sha256(key_bytes).hexdigest(),
    )

    with pytest.raises(AgentBridgeTlsDeploymentError, match="certificate SHA-256"):
        load_agent_bridge_tls_material(config)


def test_guest_tls_config_requires_exact_private_bridge_origin() -> None:
    guest_config().validate()

    with pytest.raises(AgentBridgeTlsDeploymentError, match="exact managed private"):
        guest_config(bridge_origin="https://localhost:9443").validate()

    with pytest.raises(AgentBridgeTlsDeploymentError, match="port"):
        guest_config(bridge_origin="https://172.29.240.1:443").validate()


def test_trust_root_script_never_generates_or_removes_certificates() -> None:
    script = deployment_module._GUEST_TRUST_ROOT_SCRIPT

    assert "New-SelfSignedCertificate" not in script
    assert "Remove(" not in script
    assert ".Remove(" not in script
    assert "StoreLocation]::LocalMachine" in script
    assert "StoreName]::Root" in script
    assert "$store.Add($cert)" in script
    assert "CertificateAuthority" in script


def test_install_guest_trust_root_uses_vm_id_bound_payload(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(
        vm_id: str,
        vm_name: str,
        credential: PowerShellDirectCredential,
        guest_script: str,
        *,
        timeout_seconds: int,
        secret_payload: bytes | None = None,
    ) -> dict[str, object]:
        captured.update(
            {
                "vm_id": vm_id,
                "vm_name": vm_name,
                "guest_script": guest_script,
                "timeout_seconds": timeout_seconds,
                "secret_payload": secret_payload,
            }
        )
        return exact_trust_result()

    monkeypatch.setattr(
        deployment_module,
        "run_vm_powershell_json_by_id",
        fake_run,
    )
    credential = PowerShellDirectCredential("Administrator", "secret")

    result = install_managed_guest_bridge_trust_root_by_id(
        guest_config(),
        credential,
        pem_for(ROOT_DER),
    )

    assert result["present"] is True
    assert captured["vm_id"] == VM_ID
    assert captured["vm_name"] == "HMS-VPS-000001"
    assert captured["secret_payload"] == ROOT_DER
    assert "New-SelfSignedCertificate" not in str(captured["guest_script"])


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("present", False),
        ("sha256", "0" * 64),
        ("store", r"CurrentUser\Root"),
        ("certificate_authority", False),
        ("changed", 1),
    ],
)
def test_install_guest_trust_root_rejects_inexact_evidence(
    monkeypatch,
    key: str,
    value: object,
) -> None:
    observed = exact_trust_result(**{key: value})
    monkeypatch.setattr(
        deployment_module,
        "run_vm_powershell_json_by_id",
        lambda *args, **kwargs: dict(observed),
    )

    with pytest.raises(AgentBridgeTlsDeploymentError):
        install_managed_guest_bridge_trust_root_by_id(
            guest_config(),
            PowerShellDirectCredential("Administrator", "secret"),
            pem_for(ROOT_DER),
        )


def test_live_tls_probe_uses_default_chain_and_hostname_validation() -> None:
    script = build_managed_guest_bridge_tls_probe_script(guest_config())

    assert "$client.Connect($gateway, $port)" in script
    assert "$ssl.AuthenticateAsClient($targetHost)" in script
    assert "RemoteCertificateValidationCallback" not in script
    assert "ServerCertificateCustomValidationCallback" not in script
    assert "SslStream($stream, $false)" in script
    assert "SslStream($stream, $false," not in script
    assert "$gateway = '172.29.240.1'" in script
    assert "$port = [int]9443" in script


def test_live_tls_probe_accepts_exact_managed_transport_evidence(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(
        vm_id: str,
        vm_name: str,
        credential: PowerShellDirectCredential,
        guest_script: str,
        *,
        timeout_seconds: int,
        secret_payload: bytes | None = None,
    ) -> dict[str, object]:
        captured["vm_id"] = vm_id
        captured["script"] = guest_script
        captured["timeout"] = timeout_seconds
        captured["payload"] = secret_payload
        return exact_tls_result()

    monkeypatch.setattr(
        deployment_module,
        "run_vm_powershell_json_by_id",
        fake_run,
    )

    result = probe_managed_guest_bridge_tls_by_id(
        guest_config(),
        PowerShellDirectCredential("Administrator", "secret"),
    )

    assert result["live_managed_guest_tls_proven"] is True
    assert result["vm_id"] == VM_ID
    assert result["bridge_origin"] == "https://172.29.240.1:9443"
    assert captured["payload"] is None


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("tcp_connected", False),
        ("tls_authenticated", False),
        ("local_ip", "172.29.240.11"),
        ("remote_ip", "172.29.240.2"),
        ("remote_port", 443),
        ("target_host", "localhost"),
        ("tls_protocol", "Tls11"),
        ("server_certificate_sha256", "0" * 64),
    ],
)
def test_live_tls_probe_rejects_inexact_or_weak_transport_evidence(
    monkeypatch,
    key: str,
    value: object,
) -> None:
    observed = exact_tls_result(**{key: value})
    monkeypatch.setattr(
        deployment_module,
        "run_vm_powershell_json_by_id",
        lambda *args, **kwargs: dict(observed),
    )

    with pytest.raises(AgentBridgeTlsDeploymentError):
        probe_managed_guest_bridge_tls_by_id(
            guest_config(),
            PowerShellDirectCredential("Administrator", "secret"),
        )
