from pathlib import Path

import pytest

import hms_gpt_vps.bridge_composite_activation_runner as mod


def exact_result(**overrides):
    value = {
        "ready": True,
        "status": "QUALIFIED_STOPPED",
        "service_sid": "S-1-5-80-1-2-3-4-5",
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "service_runtime_ready_proven": True,
        "tls_listener_ready_during_probe": True,
        "mcp_listener_ready_during_probe": True,
        "secure_mcp_tunnel_ready_during_probe": True,
        "runtime_process_id": 4242,
        "tunnel_process_id": 5252,
        "tunnel_executable_sha256": "a" * 64,
        "tunnel_readiness_body_class": "mcp_auth_required",
        "tunnel_stable_across_managed_guest_probe": True,
        "live_managed_guest_tls_proven": True,
        "server_certificate_sha256": "b" * 64,
        "vm_id": "12345678-1234-1234-1234-123456789abc",
        "bridge_origin": "https://172.29.240.1:9443",
        "listeners_absent_after_stop": True,
        "authenticated_agent_transport_proven": False,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
    value.update(overrides)
    return value


def test_secret_environment_is_consumed_and_not_retained():
    env = {
        mod.BOOTSTRAP_USERNAME_ENV: "Administrator",
        mod.BOOTSTRAP_PASSWORD_ENV: "TOP-SECRET",
        "KEEP": "yes",
    }
    credential = mod.load_bootstrap_credential_from_environment(env)
    assert credential.username == "Administrator"
    assert "TOP-SECRET" not in repr(credential)
    assert mod.BOOTSTRAP_USERNAME_ENV not in env
    assert mod.BOOTSTRAP_PASSWORD_ENV not in env
    assert env == {"KEEP": "yes"}


def test_result_validator_preserves_fail_closed_boundary():
    assert mod.validate_composite_activation_result(exact_result())["ready"] is True
    for patch in (
        {"pairing_ready": True},
        {"authenticated_agent_transport_proven": True},
        {"secure_mcp_tunnel_ready_during_probe": False},
        {"service_state": "Running"},
        {"runtime_process_id": True},
    ):
        with pytest.raises(mod.BridgeCompositeActivationRunnerError):
            mod.validate_composite_activation_result(exact_result(**patch))
    drift = exact_result()
    drift["unexpected"] = True
    with pytest.raises(mod.BridgeCompositeActivationRunnerError):
        mod.validate_composite_activation_result(drift)


def test_runner_uses_pinned_trust_root_composite_probe_and_create_only_proof(monkeypatch):
    calls = []
    env = {
        mod.BOOTSTRAP_USERNAME_ENV: "Administrator",
        mod.BOOTSTRAP_PASSWORD_ENV: "TOP-SECRET",
    }
    monkeypatch.setattr(mod, "require_windows_administrator", lambda: calls.append("admin"))
    monkeypatch.setattr(
        mod,
        "read_file_pinned",
        lambda path, **kwargs: calls.append(("read", path, kwargs["label"])) or b"ROOT",
    )
    monkeypatch.setattr(
        mod,
        "qualify_hms_bridge_composite_activation_probe",
        lambda request: calls.append(("probe", request.guest_credential.username)) or exact_result(),
    )
    published = {}
    monkeypatch.setattr(
        mod,
        "write_json_create_only",
        lambda path, payload, **kwargs: published.update(path=path, payload=payload, kwargs=kwargs) or path,
    )

    proof = mod.run_composite_activation_qualification(
        trust_root_certificate_path=Path("trust-root.pem"),
        proof_path=Path("proof.json"),
        environment=env,
    )

    assert calls == [
        "admin",
        ("read", Path("trust-root.pem"), "managed guest trust-root certificate"),
        ("probe", "Administrator"),
    ]
    assert published["path"] == Path("proof.json")
    assert published["payload"] == proof
    assert published["kwargs"]["label"] == "HMSBridge composite activation qualification proof"
    assert proof["schema_version"] == 1
    assert proof["qualification"] == "R002F_HMSBRIDGE_COMPOSITE_ACTIVATION"
    assert proof["result"]["pairing_ready"] is False
    assert env == {}


def test_missing_password_fails_after_removing_any_present_secret_fields():
    env = {mod.BOOTSTRAP_USERNAME_ENV: "Administrator"}
    with pytest.raises(mod.BridgeCompositeActivationRunnerError, match=mod.BOOTSTRAP_PASSWORD_ENV):
        mod.load_bootstrap_credential_from_environment(env)
    assert mod.BOOTSTRAP_USERNAME_ENV not in env
    assert mod.BOOTSTRAP_PASSWORD_ENV not in env
