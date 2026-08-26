from pathlib import Path

import pytest

import hms_gpt_vps.bridge_external_mcp_command_flow_runner as mod

SID = "S-1-5-80-1-2-3-4-5"
SOURCE_COMMIT = "4" * 40
CONTENT_SHA256 = "a" * 64


def exact_result(**overrides):
    value = {
        "ready": True,
        "status": "EXTERNAL_PRINCIPAL_READ_WITH_STABLE_TUNNEL_QUALIFIED_STOPPED",
        "service_sid": SID,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "runtime_process_id": 4242,
        "tunnel_process_id": 5252,
        "tunnel_executable_sha256": "b" * 64,
        "tunnel_readiness_body_class": "mcp_auth_required",
        "secure_mcp_tunnel_ready_during_external_flow": True,
        "tunnel_stable_across_external_flow": True,
        "agent_process_id": 6262,
        "agent_device_id": "device-1",
        "agent_boot_id": "boot-1",
        "agent_connection_epoch": 7,
        "agent_generation_stable_across_external_flow": True,
        "challenge_id": "challenge-1",
        "source_commit": SOURCE_COMMIT,
        "instance_id": "instance-1",
        "request_id": "request-1",
        "path": "README.md",
        "expected_content_sha256": CONTENT_SHA256,
        "workspace_content_size": 123,
        "workspace_content_encoding": "utf-8",
        "principal_sha256": "c" * 64,
        "pair_id": "pair-1",
        "session_id": "session-1",
        "session_epoch": 7,
        "agent_result_sha256": "d" * 64,
        "mcp_ingress_generation": "e" * 32,
        "authenticated_principal_control_path_proven": True,
        "durable_external_principal_read_proven": True,
        "runner_invoked_mcp": False,
        "runner_enqueued_agent_command": False,
        "secure_tunnel_generation_proven": True,
        "listeners_absent_after_stop": True,
        "mcp_adapter_invocation_proven": True,
        "openai_control_plane_origin_proven": False,
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


def test_result_validator_locks_boundary_and_exact_types():
    assert mod.validate_external_mcp_command_flow_result(exact_result())["ready"] is True
    for patch in (
        {"runner_invoked_mcp": True},
        {"runner_enqueued_agent_command": True},
        {"mcp_adapter_invocation_proven": False},
        {"openai_control_plane_origin_proven": True},
        {"full_bridge_command_flow_proven": True},
        {"secure_tunnel_generation_proven": False},
        {"agent_connection_epoch": True},
        {"workspace_content_size": True},
        {"workspace_content_encoding": "latin-1"},
        {"tunnel_readiness_body_class": "startup_timeout"},
        {"principal_sha256": "C" * 64},
        {"mcp_ingress_generation": "E" * 32},
        {"mcp_ingress_generation": "e" * 31},
    ):
        with pytest.raises(mod.BridgeExternalMcpCommandFlowRunnerError):
            mod.validate_external_mcp_command_flow_result(exact_result(**patch))


def test_runner_publishes_only_result_bound_to_requested_challenge(monkeypatch):
    calls = []
    env = {
        mod.BOOTSTRAP_USERNAME_ENV: "Administrator",
        mod.BOOTSTRAP_PASSWORD_ENV: "TOP-SECRET",
    }
    monkeypatch.setattr(mod, "require_windows_administrator", lambda: calls.append("admin"))
    monkeypatch.setattr(
        mod,
        "qualify_external_mcp_read_with_stable_tunnel",
        lambda request: calls.append(("qualify", request.source_commit, request.path))
        or exact_result(),
    )
    published = {}
    monkeypatch.setattr(
        mod,
        "write_json_create_only",
        lambda path, payload, **kwargs: published.update(
            path=path,
            payload=payload,
            kwargs=kwargs,
        ),
    )
    proof = mod.run_external_mcp_command_flow_qualification(
        challenge_path=Path("challenge.json"),
        proof_path=Path("proof.json"),
        source_commit=SOURCE_COMMIT,
        path="README.md",
        expected_content_sha256=CONTENT_SHA256,
        environment=env,
    )
    assert calls == ["admin", ("qualify", SOURCE_COMMIT, "README.md")]
    assert env == {}
    assert published["payload"] == proof
    assert proof["schema_version"] == 1
    assert proof["result"]["openai_control_plane_origin_proven"] is False

    monkeypatch.setattr(
        mod,
        "qualify_external_mcp_read_with_stable_tunnel",
        lambda request: exact_result(path="other.txt"),
    )
    with pytest.raises(
        mod.BridgeExternalMcpCommandFlowRunnerError,
        match="requested challenge authority",
    ):
        mod.run_external_mcp_command_flow_qualification(
            challenge_path=Path("challenge-2.json"),
            proof_path=Path("proof-2.json"),
            source_commit=SOURCE_COMMIT,
            path="README.md",
            expected_content_sha256=CONTENT_SHA256,
            environment={
                mod.BOOTSTRAP_USERNAME_ENV: "Administrator",
                mod.BOOTSTRAP_PASSWORD_ENV: "TOP-SECRET",
            },
        )


def test_runner_rejects_same_challenge_and_proof_path_before_secret_consumption():
    env = {
        mod.BOOTSTRAP_USERNAME_ENV: "Administrator",
        mod.BOOTSTRAP_PASSWORD_ENV: "TOP-SECRET",
    }
    with pytest.raises(
        mod.BridgeExternalMcpCommandFlowRunnerError,
        match="distinct",
    ):
        mod.run_external_mcp_command_flow_qualification(
            challenge_path=Path("same.json"),
            proof_path=Path("same.json"),
            source_commit=SOURCE_COMMIT,
            path="README.md",
            expected_content_sha256=CONTENT_SHA256,
            environment=env,
        )
    assert env[mod.BOOTSTRAP_PASSWORD_ENV] == "TOP-SECRET"
