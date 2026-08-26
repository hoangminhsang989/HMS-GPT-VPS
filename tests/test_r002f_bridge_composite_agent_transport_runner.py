from pathlib import Path

import pytest

import hms_gpt_vps.bridge_composite_agent_transport_runner as mod


def exact_result(**overrides):
    value = {
        "ready": True,
        "status": "AUTHENTICATED_AGENT_TRANSPORT_WITH_TUNNEL_QUALIFIED_STOPPED",
        "service_sid": "S-1-5-80-1-2-3-4-5",
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "runtime_process_id": 4242,
        "tunnel_process_id": 5252,
        "tunnel_executable_sha256": "a" * 64,
        "tunnel_readiness_body_class": "mcp_auth_required",
        "secure_mcp_tunnel_ready_during_transport": True,
        "tunnel_stable_across_authenticated_transport": True,
        "agent_process_id": 6262,
        "agent_device_id": "device-1",
        "agent_boot_id": "boot-1",
        "agent_connection_epoch": 7,
        "authenticated_hello_proven": True,
        "authenticated_heartbeat_proven": True,
        "authenticated_poll_proven": True,
        "authenticated_result_proven": True,
        "authenticated_agent_transport_proven": True,
        "qualification_action": "git.status",
        "qualification_request_id": "req-1",
        "qualification_result_outcome": "ok",
        "listeners_absent_after_stop": True,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
    value.update(overrides)
    return value


def test_secret_environment_is_consumed():
    env = {
        mod.BOOTSTRAP_USERNAME_ENV: "Administrator",
        mod.BOOTSTRAP_PASSWORD_ENV: "TOP-SECRET",
    }
    credential = mod.load_bootstrap_credential_from_environment(env)
    assert credential.username == "Administrator"
    assert "TOP-SECRET" not in repr(credential)
    assert env == {}


def test_result_validator_requires_tunnel_and_authenticated_transport_but_not_full_flow():
    assert mod.validate_composite_agent_transport_result(exact_result())["ready"] is True
    for patch in (
        {"secure_mcp_tunnel_ready_during_transport": False},
        {"authenticated_agent_transport_proven": False},
        {"full_bridge_command_flow_proven": True},
        {"pairing_ready": True},
        {"qualification_action": "shell.exec"},
        {"agent_connection_epoch": True},
    ):
        with pytest.raises(mod.BridgeCompositeAgentTransportRunnerError):
            mod.validate_composite_agent_transport_result(exact_result(**patch))


def test_runner_executes_composite_transport_and_publishes_create_only_proof(monkeypatch):
    calls = []
    env = {
        mod.BOOTSTRAP_USERNAME_ENV: "Administrator",
        mod.BOOTSTRAP_PASSWORD_ENV: "TOP-SECRET",
    }
    monkeypatch.setattr(mod, "require_windows_administrator", lambda: calls.append("admin"))
    monkeypatch.setattr(
        mod,
        "qualify_authenticated_agent_transport_with_secure_tunnel",
        lambda request: calls.append(("transport", request.guest_credential.username)) or exact_result(),
    )
    published = {}
    monkeypatch.setattr(
        mod,
        "write_json_create_only",
        lambda path, payload, **kwargs: published.update(path=path, payload=payload, kwargs=kwargs) or path,
    )
    proof = mod.run_composite_agent_transport_qualification(
        proof_path=Path("transport-proof.json"),
        environment=env,
    )
    assert calls == ["admin", ("transport", "Administrator")]
    assert env == {}
    assert published["path"] == Path("transport-proof.json")
    assert published["payload"] == proof
    assert proof["schema_version"] == 1
    assert proof["result"]["full_bridge_command_flow_proven"] is False


def test_missing_username_and_password_are_never_cli_fallbacks():
    env = {}
    with pytest.raises(mod.BridgeCompositeAgentTransportRunnerError, match=mod.BOOTSTRAP_USERNAME_ENV):
        mod.load_bootstrap_credential_from_environment(env)
    assert env == {}
