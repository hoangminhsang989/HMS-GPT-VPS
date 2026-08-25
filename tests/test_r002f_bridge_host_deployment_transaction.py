from pathlib import Path
from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_host_deployment_transaction as mod
from hms_gpt_vps.pairing_exchange import PairingExchangeKey

SID = mod.HMS_BRIDGE_EXPECTED_SERVICE_SID


def test_service_sid_derivation_matches_microsoft_alg_example_and_frozen_hmsbridge():
    assert mod.derive_windows_service_sid("ALG") == (
        "S-1-5-80-2387347252-3645287876-2469496166-3824418187-3586569773"
    )
    assert mod.derive_hms_bridge_service_sid() == SID


def test_request_repr_does_not_expose_secret_fields():
    request = mod.BridgeHostDeploymentRequest(
        source_package_root=Path("package"),
        package_manifest=SimpleNamespace(),  # type: ignore[arg-type]
        runtime_config=SimpleNamespace(),  # type: ignore[arg-type]
        agent_credential=SimpleNamespace(secret=b"AGENT-SECRET"),  # type: ignore[arg-type]
        oauth_credential=SimpleNamespace(client_secret="OAUTH-SECRET"),  # type: ignore[arg-type]
        tls_certificate_pem=b"CERTIFICATE-SECRETISH",
        tls_private_key_pem=b"PRIVATE-KEY-SECRET",
        guest_credential=SimpleNamespace(password="GUEST-PASSWORD"),  # type: ignore[arg-type]
        trust_root_certificate_pem=b"ROOT-CERTIFICATE",
    )
    text = repr(request)
    for secret in ("AGENT-SECRET", "OAUTH-SECRET", "PRIVATE-KEY-SECRET", "GUEST-PASSWORD"):
        assert secret not in text


def test_create_only_transaction_orders_authorities_and_never_starts_service(monkeypatch):
    order = []
    manifest = SimpleNamespace(sha256="a" * 64)
    agent = SimpleNamespace(instance_id="HMS-VPS-1", device_id="device-1")
    oauth = SimpleNamespace(issuer_url="https://issuer.example", client_id="bridge-client", client_secret="secret")
    runtime = SimpleNamespace(
        secret_storage=object(),
        tls=SimpleNamespace(
            material=SimpleNamespace(
                certificate_der_sha256="b" * 64,
                private_key_file_sha256="c" * 64,
            )
        ),
    )
    runtime_config = SimpleNamespace(
        mcp_issuer_url=oauth.issuer_url,
        to_runtime_config=lambda sid: (order.append("compile"), runtime)[1],
    )
    request = SimpleNamespace(
        validate=lambda: order.append("validate"),
        source_package_root=Path("source"),
        package_manifest=manifest,
        runtime_config=runtime_config,
        agent_credential=agent,
        oauth_credential=oauth,
        tls_certificate_pem=b"CERT",
        tls_private_key_pem=b"KEY",
        guest_credential=object(),
        trust_root_certificate_pem=b"ROOT",
    )

    monkeypatch.setattr(mod, "stage_bridge_package_create_only", lambda *a: (order.append("package"), SimpleNamespace(ready=True, binary_sha256="a" * 64, binary_path=str(mod.DEFAULT_BRIDGE_BINARY_PATH)))[1])
    monkeypatch.setattr(mod, "install_hms_bridge_service_authority", lambda cfg: (order.append("scm"), {"ready": True, "service_sid": SID})[1])
    monkeypatch.setattr(mod, "finalize_bridge_package_service_acl", lambda m: (order.append("package_acl"), SimpleNamespace(ready=True, service_acl_finalized=True))[1])
    monkeypatch.setattr(mod, "provision_bridge_runtime_layout", lambda c: (order.append("layout"), {"ready": True, "service_sid": SID})[1])
    monkeypatch.setattr(mod, "publish_bridge_tls_material_create_only", lambda *a: (order.append("tls_material"), {"ready": True, "runtime_listener_started": False})[1])
    identity_queue = [
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
        {"service_sid": SID, "service_state": "Stopped", "service_start_mode": "Manual"},
    ]
    monkeypatch.setattr(mod, "prove_hms_bridge_provisioning_identity", lambda: (order.append("identity"), identity_queue.pop(0))[1])
    monkeypatch.setattr(mod, "provision_bridge_service_pairing_key", lambda c: (order.append("pairing_key"), PairingExchangeKey(b"p" * 32))[1])
    monkeypatch.setattr(mod, "provision_bridge_service_agent_credential", lambda *a: (order.append("agent_credential"), agent)[1])
    monkeypatch.setattr(mod, "provision_agent_bridge_production_tls_prerequisites", lambda *a: (order.append("tls_prereq"), {"tls_material_preflight_ready": True, "firewall_ready": True, "guest_trust_root_present": True, "runtime_listener_started": False})[1])
    monkeypatch.setattr(mod, "publish_bridge_service_runtime_config_create_only", lambda c: (order.append("config"), {"ready": True, "service_sid": SID})[1])
    monkeypatch.setattr(mod, "provision_bridge_oauth_introspection_credential_from_stdin", lambda stream: (order.append("oauth"), {"ready": True, "service_sid": SID, "secret_acl_exact": True, "issuer_url": oauth.issuer_url, "client_id": oauth.client_id})[1])
    monkeypatch.setattr(mod, "load_protected_bridge_oauth_introspection_credential", lambda issuer: (order.append("oauth_load"), oauth)[1])
    monkeypatch.setattr(mod, "load_protected_bridge_service_runtime_config", lambda: (order.append("final_config"), runtime_config)[1])
    monkeypatch.setattr(mod, "canonical_bridge_service_runtime_config_bytes", lambda c: b"CONFIG")
    monkeypatch.setattr(mod, "load_agent_bridge_tls_material", lambda m: (order.append("final_tls"), SimpleNamespace(validate=lambda: None))[1])

    result = mod.deploy_hms_bridge_host_create_only(request)  # type: ignore[arg-type]
    assert result["ready"] is True
    assert result["status"] == "STAGED_NOT_EXECUTED"
    assert result["service_state"] == "Stopped"
    assert result["runtime_listener_started"] is False
    assert result["pairing_ready"] is False
    assert result["authenticated_agent_transport_proven"] is False
    assert order == [
        "validate", "package", "scm", "package_acl", "layout", "compile",
        "tls_material", "identity", "pairing_key", "agent_credential", "identity",
        "tls_prereq", "config", "oauth", "oauth_load", "final_config", "final_tls",
        "identity",
    ]


def test_transaction_wraps_stage_failure_without_continuing(monkeypatch):
    order = []
    request = SimpleNamespace(
        validate=lambda: order.append("validate"),
        source_package_root=Path("source"),
        package_manifest=SimpleNamespace(sha256="a" * 64),
    )
    monkeypatch.setattr(mod, "stage_bridge_package_create_only", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(mod.BridgeHostDeploymentTransactionError) as exc:
        mod.deploy_hms_bridge_host_create_only(request)  # type: ignore[arg-type]
    assert exc.value.stage == "package_stage"
    assert order == ["validate"]
