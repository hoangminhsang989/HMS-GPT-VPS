from pathlib import PureWindowsPath
import subprocess

import pytest

import hms_gpt_vps.secure_mcp_tunnel_openai_origin_qualification as mod

SERVICE_PID = 4242
TUNNEL_PID = 5252
GENERATION = "d" * 32
EXE = r"C:\ProgramData\HMS-GPT-VPS\Bridge\tunnel-client\v0.0.12\tunnel-client-runtime.exe"
URL_FILE = (
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-"
    + GENERATION
    + r"\health-url.txt"
)


def evidence(**overrides):
    value = {
        "ready": True,
        "service_process_id": SERVICE_PID,
        "tunnel_process_id": TUNNEL_PID,
        "tunnel_parent_process_id": SERVICE_PID,
        "tunnel_executable_path": EXE,
        "tunnel_executable_sha256": "a" * 64,
        "health_attempt_path": str(PureWindowsPath(URL_FILE).parent),
        "health_url_path": URL_FILE,
        "health_base_url": "http://127.0.0.1:54321",
        "health_listener_host": "127.0.0.1",
        "health_listener_port": 54321,
        "readiness_url": "http://127.0.0.1:54321/readyz",
        "readiness_status_code": 200,
        "readiness_body_class": "mcp_auth_required",
        "mcp_ingress_generation": GENERATION,
    }
    value.update(overrides)
    return value


def probe_for(value):
    argv = mod._expected_runtime_argv(value)
    return {
        "process_id": TUNNEL_PID,
        "parent_process_id": SERVICE_PID,
        "executable_path": EXE,
        "command_line": subprocess.list2cmdline(list(argv)),
    }


def test_live_origin_launch_profile_is_exact(monkeypatch):
    value = evidence()
    monkeypatch.setattr(
        mod,
        "qualify_running_secure_mcp_tunnel_with_ingress_generation",
        lambda **kwargs: dict(value),
    )
    monkeypatch.setattr(mod, "run_powershell_json", lambda *args, **kwargs: probe_for(value))
    result = mod.qualify_running_secure_mcp_tunnel_with_openai_origin_profile(
        service_sid="S-1-5-80-1-2-3-4-5",
        service_process_id=SERVICE_PID,
    )
    assert result["openai_origin_launch_profile_proven"] is True
    assert len(result["launch_command_line_sha256"]) == 64
    assert result["mcp_ingress_generation"] == GENERATION


def test_config_or_control_plane_override_arg_fails_closed(monkeypatch):
    value = evidence()
    monkeypatch.setattr(
        mod,
        "qualify_running_secure_mcp_tunnel_with_ingress_generation",
        lambda **kwargs: dict(value),
    )
    bad = probe_for(value)
    bad["command_line"] += " --control-plane.base-url http://127.0.0.1:9"
    monkeypatch.setattr(mod, "run_powershell_json", lambda *args, **kwargs: bad)
    with pytest.raises(
        mod.SecureMcpTunnelOpenAiOriginQualificationError,
        match="closed OpenAI runtime launch profile",
    ):
        mod.qualify_running_secure_mcp_tunnel_with_openai_origin_profile(
            service_sid="S-1-5-80-1-2-3-4-5",
            service_process_id=SERVICE_PID,
        )


def test_process_identity_or_generation_drift_fails_closed(monkeypatch):
    for value in (
        evidence(mcp_ingress_generation="Z" * 32),
        evidence(tunnel_executable_sha256="A" * 64),
    ):
        monkeypatch.setattr(
            mod,
            "qualify_running_secure_mcp_tunnel_with_ingress_generation",
            lambda value=value, **kwargs: dict(value),
        )
        monkeypatch.setattr(mod, "run_powershell_json", lambda *args, **kwargs: probe_for(evidence()))
        with pytest.raises(mod.SecureMcpTunnelOpenAiOriginQualificationError):
            mod.qualify_running_secure_mcp_tunnel_with_openai_origin_profile(
                service_sid="S-1-5-80-1-2-3-4-5",
                service_process_id=SERVICE_PID,
            )
