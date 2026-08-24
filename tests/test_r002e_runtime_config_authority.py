from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
    AgentServiceRuntimeConfigError,
    load_agent_service_runtime_config,
)
from hms_gpt_vps import agent_service_runtime_config as runtime_config_module


def _config(tmp_path: Path, *, schema_version: int = AGENT_SERVICE_RUNTIME_SCHEMA_VERSION):
    return AgentServiceRuntimeConfig(
        schema_version=schema_version,
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=str((tmp_path / "workspace").absolute()),
        state_root=str((tmp_path / "state").absolute()),
        python_executable=str((tmp_path / "tools" / "python.exe").absolute()),
        git_executable=str((tmp_path / "tools" / "git.exe").absolute()),
        health_port=8765,
    )


def test_direct_runtime_config_rejects_boolean_schema_version(tmp_path: Path) -> None:
    config = _config(tmp_path, schema_version=True)  # type: ignore[arg-type]
    with pytest.raises(AgentServiceRuntimeConfigError, match="schema_version must be an integer"):
        config.validate()


def test_runtime_config_loader_rejects_symlinked_parent(tmp_path: Path) -> None:
    real = tmp_path / "runtime-real"
    real.mkdir()
    target = real / "agent-runtime.json"
    target.write_text(_config(tmp_path).to_json(), encoding="utf-8")
    linked = tmp_path / "runtime-linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(PermissionError, match="traverse a link or reparse point"):
        load_agent_service_runtime_config(linked / "agent-runtime.json")


def test_runtime_config_loader_rejects_target_substitution_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "agent-runtime.json"
    data = _config(tmp_path).to_json()
    path.write_text(data, encoding="utf-8")
    displaced = tmp_path / "agent-runtime-opened.json"
    original_open = runtime_config_module.os.open
    mutated = False

    def racing_open(target, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal mutated
        fd = original_open(target, flags, *args, **kwargs)
        if not mutated:
            mutated = True
            Path(target).replace(displaced)
            Path(target).write_text(data, encoding="utf-8")
        return fd

    monkeypatch.setattr(runtime_config_module.os, "open", racing_open)

    with pytest.raises(PermissionError, match="authority changed during open"):
        load_agent_service_runtime_config(path)

    assert path.exists()
    assert displaced.exists()
