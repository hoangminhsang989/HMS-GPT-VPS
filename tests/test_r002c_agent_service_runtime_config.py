from __future__ import annotations

import json
from pathlib import Path

import pytest

from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    MAX_AGENT_RUNTIME_CONFIG_BYTES,
    AgentServiceRuntimeConfig,
    AgentServiceRuntimeConfigError,
    load_agent_service_runtime_config,
    parse_agent_service_runtime_config,
)


def make_config(tmp_path: Path) -> AgentServiceRuntimeConfig:
    return AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=str((tmp_path / "workspace").resolve()),
        state_root=str((tmp_path / "state").resolve()),
        python_executable=str((tmp_path / "tools" / "python.exe").resolve()),
        git_executable=str((tmp_path / "tools" / "git.exe").resolve()),
        health_port=8765,
    )


def test_runtime_config_canonical_json_round_trip(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    encoded = config.to_json().encode("utf-8")

    parsed = parse_agent_service_runtime_config(encoded)

    assert parsed == config
    assert parsed.to_json() == config.to_json()
    guest = parsed.to_guest_runtime_config()
    assert guest.instance_id == "hms-01"
    assert guest.project_id == "project-01"
    assert guest.bridge_origin == "https://bridge.example"


def test_runtime_config_accepts_absolute_windows_guest_paths_cross_platform() -> None:
    config = AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=r"C:\HMS-Workspace",
        state_root=r"C:\ProgramData\HMS-GPT-VPS\State",
        python_executable=r"C:\Program Files\Python\python.exe",
        git_executable=r"C:\Program Files\Git\cmd\git.exe",
        health_port=8765,
    )

    config.validate()
    assert json.loads(config.to_json())["workspace_root"] == r"C:\HMS-Workspace"


def test_runtime_config_rejects_unknown_fields_including_secret_like_data(tmp_path: Path) -> None:
    raw = make_config(tmp_path).to_dict()
    raw["device_secret"] = "must-not-be-here"

    with pytest.raises(AgentServiceRuntimeConfigError, match="unknown=device_secret"):
        parse_agent_service_runtime_config(json.dumps(raw).encode("utf-8"))


def test_runtime_config_rejects_missing_field_wrong_schema_and_boolean_port(tmp_path: Path) -> None:
    raw = make_config(tmp_path).to_dict()
    raw.pop("git_executable")
    with pytest.raises(AgentServiceRuntimeConfigError, match="missing=git_executable"):
        parse_agent_service_runtime_config(json.dumps(raw).encode("utf-8"))

    raw = make_config(tmp_path).to_dict()
    raw["schema_version"] = 999
    with pytest.raises(AgentServiceRuntimeConfigError, match="schema_version"):
        parse_agent_service_runtime_config(json.dumps(raw).encode("utf-8"))

    raw = make_config(tmp_path).to_dict()
    raw["health_port"] = True
    with pytest.raises(AgentServiceRuntimeConfigError, match="health_port must be an integer"):
        parse_agent_service_runtime_config(json.dumps(raw).encode("utf-8"))


def test_runtime_config_rejects_http_and_relative_paths(tmp_path: Path) -> None:
    raw = make_config(tmp_path).to_dict()
    raw["bridge_origin"] = "http://bridge.example"
    with pytest.raises(ValueError, match="https"):
        parse_agent_service_runtime_config(json.dumps(raw).encode("utf-8"))

    raw = make_config(tmp_path).to_dict()
    raw["python_executable"] = "python.exe"
    with pytest.raises(AgentServiceRuntimeConfigError, match="absolute path"):
        parse_agent_service_runtime_config(json.dumps(raw).encode("utf-8"))


def test_runtime_config_parser_rejects_non_object_invalid_utf8_and_oversize() -> None:
    with pytest.raises(AgentServiceRuntimeConfigError, match="JSON object"):
        parse_agent_service_runtime_config(b"[]")
    with pytest.raises(AgentServiceRuntimeConfigError, match="UTF-8"):
        parse_agent_service_runtime_config(b"\xff")
    with pytest.raises(AgentServiceRuntimeConfigError, match="too large"):
        parse_agent_service_runtime_config(b"x" * (MAX_AGENT_RUNTIME_CONFIG_BYTES + 1))


def test_runtime_config_loader_requires_absolute_regular_non_symlink_file(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    path = (tmp_path / "agent-runtime.json").resolve()
    path.write_text(config.to_json(), encoding="utf-8")

    assert load_agent_service_runtime_config(path) == config

    with pytest.raises(AgentServiceRuntimeConfigError, match="absolute"):
        load_agent_service_runtime_config(Path("agent-runtime.json"))

    missing = (tmp_path / "missing.json").resolve()
    with pytest.raises(FileNotFoundError):
        load_agent_service_runtime_config(missing)

    link = tmp_path / "runtime-link.json"
    try:
        link.symlink_to(path)
    except OSError:
        return
    with pytest.raises(PermissionError, match="symbolic link"):
        load_agent_service_runtime_config(link.resolve(strict=False) if False else link)
