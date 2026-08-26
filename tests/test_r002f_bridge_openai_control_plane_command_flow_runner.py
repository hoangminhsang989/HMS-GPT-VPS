from pathlib import Path
from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_openai_control_plane_command_flow_runner as mod

SOURCE_COMMIT = "4" * 40
CONTENT_SHA = "a" * 64
GENERATION = "d" * 32


def result(**overrides):
    value = {
        "ready": True,
        "status": "OPENAI_CONTROL_PLANE_PRINCIPAL_READ_QUALIFIED_STOPPED",
        "service_sid": "S-1-5-80-1-2-3-4-5",
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "runtime_process_id": 4242,
        "tunnel_process_id": 5252,
        "tunnel_executable_sha256": "b" * 64,
        "tunnel_readiness_body_class": "mcp_auth_required",
        "mcp_ingress_generation": GENERATION,
        "launch_command_line_sha256": "e" * 64,
        "openai_origin_kind": "OPENAI_TUNNEL_CONTROL_PLANE_COMMAND",
        "openai_tunnel_upstream_commit": "881c9a8fed7cccbe6607cd419863bbca506b8215",
        "openai_tunnel_upstream_tree": "fee5968ecb711a6cd1dd4df9f322f62fae613b28",
        "openai_tunnel_release_asset_sha256": "0721098f9edda72cc36f938adcb12cd6a0c49c6c0be7ad6ab6e412f966585f2e",
        "challenge_id": "challenge-1",
        "source_commit": SOURCE_COMMIT,
        "instance_id": "instance-1",
        "request_id": "request-1",
        "path": "README.md",
        "expected_content_sha256": CONTENT_SHA,
        "workspace_content_size": 10,
        "workspace_content_encoding": "utf-8",
        "principal_sha256": "c" * 64,
        "pair_id": "pair-1",
        "session_id": "session-1",
        "session_epoch": 7,
        "agent_result_sha256": "d" * 64,
        "authenticated_principal_control_path_proven": True,
        "durable_external_principal_read_proven": True,
        "runner_invoked_mcp": False,
        "runner_enqueued_agent_command": False,
        "mcp_adapter_invocation_proven": True,
        "secure_tunnel_generation_proven": True,
        "openai_tunnel_launch_profile_proven": True,
        "openai_control_plane_origin_proven": True,
        "chatgpt_ui_origin_proven": False,
        "full_bridge_command_flow_proven": False,
        "listeners_absent_after_stop": True,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
    value.update(overrides)
    return value


def test_validator_accepts_only_narrow_origin_proof():
    assert mod.validate_openai_control_plane_command_flow_result(result()) == result()
    for changed in (
        result(openai_control_plane_origin_proven=False),
        result(chatgpt_ui_origin_proven=True),
        result(full_bridge_command_flow_proven=True),
        result(mcp_ingress_generation="Z" * 32),
        result(openai_tunnel_upstream_commit="0" * 40),
        result(launch_command_line_sha256="A" * 64),
    ):
        with pytest.raises(mod.BridgeOpenAiControlPlaneCommandFlowRunnerError):
            mod.validate_openai_control_plane_command_flow_result(changed)


def test_runner_publishes_create_only_proof_and_scrubs_bootstrap(monkeypatch):
    env = {
        "HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME": "Administrator",
        "HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD": "secret",
    }
    monkeypatch.setattr(mod, "require_windows_administrator", lambda: None)

    def load_credential(environment):
        username = environment.pop("HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME")
        password = environment.pop("HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD")
        return SimpleNamespace(username=username, password=password, validate=lambda: None)

    monkeypatch.setattr(mod, "load_bootstrap_credential_from_environment", load_credential)
    monkeypatch.setattr(
        mod,
        "BridgeExternalMcpCommandFlowQualificationRequest",
        lambda **kwargs: SimpleNamespace(validate=lambda: None, **kwargs),
    )
    monkeypatch.setattr(mod, "qualify_openai_control_plane_mcp_read", lambda request: result())
    published = {}
    monkeypatch.setattr(
        mod,
        "write_json_create_only",
        lambda path, payload, **kwargs: published.update(path=path, payload=payload, kwargs=kwargs),
    )
    proof = mod.run_openai_control_plane_command_flow_qualification(
        challenge_path=Path("challenge.json"),
        proof_path=Path("proof.json"),
        source_commit=SOURCE_COMMIT,
        path="README.md",
        expected_content_sha256=CONTENT_SHA,
        environment=env,
    )
    assert env == {}
    assert proof["qualification"] == "R002F_OPENAI_CONTROL_PLANE_COMMAND_FLOW"
    assert proof["result"]["openai_control_plane_origin_proven"] is True
    assert proof["result"]["chatgpt_ui_origin_proven"] is False
    assert published["path"] == Path("proof.json")
    assert "secret" not in repr(published["payload"])


def test_runner_rejects_same_challenge_and_proof_path_before_mutation(monkeypatch):
    monkeypatch.setattr(mod, "require_windows_administrator", lambda: (_ for _ in ()).throw(AssertionError("must not run")))
    with pytest.raises(
        mod.BridgeOpenAiControlPlaneCommandFlowRunnerError,
        match="must be distinct",
    ):
        mod.run_openai_control_plane_command_flow_qualification(
            challenge_path=Path("same.json"),
            proof_path=Path("same.json"),
            source_commit=SOURCE_COMMIT,
            path="README.md",
            expected_content_sha256=CONTENT_SHA,
        )
